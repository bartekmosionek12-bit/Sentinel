"""API Etapu 2: findingi, feed zagrożeń, kolejka weryfikacji, powiadomienia, statystyki."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DispatcherDep, RulebookDep, SessionDep
from app.api.schemas import (
    AffectedAssetOut,
    AssetDetailOut,
    AssetHistoryOut,
    AssetImportIn,
    AssetImportOut,
    AssetOut,
    AssetRef,
    FeedStatusOut,
    FindingDetailOut,
    FindingEventOut,
    FindingOut,
    FindingPatchIn,
    NotificationOut,
    Page,
    ReviewDecisionIn,
    ReviewDecisionOut,
    ReviewItemOut,
    RiskLevel,
    ScanRunOut,
    SignalDecisionOut,
    SignalItemOut,
    SoftwareOut,
    StatsOut,
    TaskOut,
    ThreatFeedOut,
    ThreatOut,
    VulnRef,
)
from app.core import audit
from app.feeds.service import FEEDS
from app.iam.deps import AuditSinkDep, ensure, require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.inventory.service import import_assets, parse_assets_csv
from app.matching.engine import ACTIVE_STATUSES, CandidateError, decide_candidate
from app.matching.signals import SignalError, decide_signal
from app.models import (
    Asset,
    AssetHistory,
    FeedSync,
    Finding,
    FindingEvent,
    MatchCandidate,
    Notification,
    ScanAction,
    ScanRun,
    SignalMatch,
    Software,
    Vulnerability,
)
from app.notifications.engine import notify
from app.pipeline import analyze
from app.runtime import channel_sender

router = APIRouter(prefix="/api", route_class=RedactingRoute)

Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0)]
# Statusy wymagające uzasadnienia: zamykają finding bez usunięcia przyczyny.
NEEDS_REASON = ("accepted_risk", "false_positive")


def _finding_out(finding: Finding, asset: Asset, vuln: Vulnerability | None) -> FindingOut:
    evidence = finding.evidence or {}
    return FindingOut(
        id=finding.id,
        type=finding.type,
        status=finding.status,
        risk_score=finding.risk_score,
        risk_level=finding.risk_level,
        summary=str((finding.risk_breakdown or {}).get("summary", "")),
        asset=AssetRef.model_validate(asset),
        vulnerability=VulnRef.model_validate(vuln) if vuln else None,
        product=evidence.get("product"),
        version=evidence.get("version"),
        port=evidence.get("port"),
        fixed_version=evidence.get("fixed_version"),
        assignee=finding.assignee,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
    )


@router.get(
    "/findings",
    response_model=Page[FindingOut],
    tags=["zagrożenia"],
    dependencies=[Depends(require("findings:read"))],
)
def list_findings(
    session: SessionDep,
    status_filter: Annotated[str, Query(alias="status")] = "active",
    level: RiskLevel | None = None,
    asset_id: uuid.UUID | None = None,
    kev: bool | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> Page[FindingOut]:
    """Findingi posortowane od najwyższego ryzyka. `status=active` to otwarte i w toku."""
    query = (
        select(Finding, Asset, Vulnerability)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
    )
    if status_filter == "active":
        query = query.where(Finding.status.in_(ACTIVE_STATUSES))
    elif status_filter != "all":
        query = query.where(Finding.status == status_filter)
    if level:
        query = query.where(Finding.risk_level == level)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if kev is not None:
        query = query.where(Vulnerability.in_kev.is_(kev))
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.execute(
        query.order_by(Finding.risk_score.desc(), Finding.first_seen).limit(limit).offset(offset)
    ).all()
    return Page[FindingOut](
        items=[_finding_out(f, a, v) for f, a, v in rows], total=total, limit=limit, offset=offset
    )


def _finding_detail(session: Session, finding_id: uuid.UUID) -> FindingDetailOut:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono findingu")
    asset = session.get(Asset, finding.asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zasób findingu już nie istnieje")
    vuln = (
        session.get(Vulnerability, finding.vulnerability_id) if finding.vulnerability_id else None
    )
    events = session.scalars(
        select(FindingEvent)
        .where(FindingEvent.finding_id == finding.id)
        .order_by(FindingEvent.created_at.desc())
    ).all()
    base = _finding_out(finding, asset, vuln)
    return FindingDetailOut(
        **base.model_dump(),
        description=vuln.description if vuln else "",
        references=[str(r) for r in (vuln.references if vuln else [])],
        kev_required_action=vuln.kev_required_action if vuln else None,
        risk_breakdown=finding.risk_breakdown,
        evidence=finding.evidence,
        events=[FindingEventOut.model_validate(e) for e in events],
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingDetailOut,
    tags=["zagrożenia"],
    dependencies=[Depends(require("findings:read"))],
)
def get_finding(finding_id: uuid.UUID, session: SessionDep) -> FindingDetailOut:
    return _finding_detail(session, finding_id)


@router.patch("/findings/{finding_id}", response_model=FindingDetailOut, tags=["zagrożenia"])
def update_finding(
    finding_id: uuid.UUID,
    payload: FindingPatchIn,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("findings:update"))],
    request: Request,
    audit_sink: AuditSinkDep,
) -> FindingDetailOut:
    """Zmiana statusu albo osoby odpowiedzialnej. Ocena ryzyka nie jest edytowalna.
    Akceptacja ryzyka wymaga dodatkowo uprawnienia `risk:accept`."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono findingu")
    if payload.status == "accepted_risk":
        ensure(principal, "risk:accept", request, audit_sink)
    before = {"status": finding.status, "assignee": finding.assignee}
    if payload.status in NEEDS_REASON and len(payload.reason.strip()) < 3:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Akceptacja ryzyka i fałszywy alarm wymagają uzasadnienia",
        )
    if payload.status is not None:
        finding.status = payload.status
    if "assignee" in payload.model_fields_set:
        finding.assignee = payload.assignee
    after = {"status": finding.status, "assignee": finding.assignee}
    if after != before:
        reason = payload.reason.strip() or "Zmiana wprowadzona przez operatora"
        session.add(
            FindingEvent(
                finding_id=finding.id,
                kind="status_changed" if before["status"] != after["status"] else "assigned",
                before=before,
                after=after,
                actor=principal.actor,
                reason=reason,
            )
        )
        audit.record(
            session,
            audit.AuditEvent(
                actor=principal.actor,
                action="finding_updated",
                reason=reason,
                inputs={"before": before, "after": after},
                object_type="finding",
                object_id=str(finding.id),
            ),
        )
    session.flush()
    return _finding_detail(session, finding_id)


@router.get(
    "/threat-feed",
    response_model=ThreatFeedOut,
    tags=["zagrożenia"],
    dependencies=[Depends(require("findings:read"))],
)
def threat_feed(
    session: SessionDep,
    scope: Literal["ours", "all"] = "ours",
    limit: Limit = 100,
) -> ThreatFeedOut:
    """Feed zagrożeń: „które nas dotyczą” (są aktywne findingi) albo wszystkie znane."""
    new_since = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    affected: dict[uuid.UUID, list[AffectedAssetOut]] = {}
    for finding, asset in session.execute(
        select(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.status.in_(ACTIVE_STATUSES), Finding.vulnerability_id.is_not(None))
        .order_by(Finding.risk_score.desc())
    ):
        if finding.vulnerability_id is None:
            continue
        affected.setdefault(finding.vulnerability_id, []).append(
            AffectedAssetOut(
                finding_id=finding.id,
                asset_id=asset.id,
                asset_name=asset.name,
                risk_score=finding.risk_score,
                risk_level=finding.risk_level,
            )
        )
    total = session.scalar(select(func.count()).select_from(Vulnerability)) or 0
    new_total = (
        session.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.first_ingested >= new_since)
        )
        or 0
    )
    ours = (
        session.scalars(select(Vulnerability).where(Vulnerability.id.in_(list(affected)))).all()
        if affected
        else []
    )
    if scope == "ours":
        vulns = sorted(ours, key=lambda v: (-affected[v.id][0].risk_score, v.cve_id))[:limit]
    else:
        vulns = list(
            session.scalars(
                select(Vulnerability)
                .order_by(Vulnerability.published.desc().nulls_last(), Vulnerability.cve_id)
                .limit(limit)
            )
        )

    def is_new(vuln: Vulnerability) -> bool:
        ingested = vuln.first_ingested
        if ingested.tzinfo is None:
            ingested = ingested.replace(tzinfo=UTC)
        return ingested >= new_since

    return ThreatFeedOut(
        items=[
            ThreatOut(
                cve_id=v.cve_id,
                description=v.description,
                cvss_score=v.cvss_score,
                epss=v.epss,
                in_kev=v.in_kev,
                kev_date_added=v.kev_date_added,
                has_public_exploit=v.has_public_exploit,
                published=v.published,
                first_ingested=v.first_ingested,
                is_new=is_new(v),
                affected_assets=affected.get(v.id, []),
                max_risk=affected[v.id][0].risk_score if v.id in affected else None,
            )
            for v in vulns
        ],
        total=total,
        total_ours=len(ours),
        new_total=new_total,
        new_ours=sum(1 for v in ours if is_new(v)),
        new_since=new_since,
    )


def _feed_status(session: Session) -> list[FeedStatusOut]:
    result = []
    for name in FEEDS:
        sync = session.scalar(
            select(FeedSync)
            .where(FeedSync.feed == name)
            .order_by(FeedSync.started_at.desc())
            .limit(1)
        )
        result.append(
            FeedStatusOut(
                feed=name,
                mode=sync.mode if sync else None,
                status=sync.status if sync else "never",
                items_new=sync.items_new if sync else 0,
                items_updated=sync.items_updated if sync else 0,
                error=sync.error if sync else None,
                finished_at=sync.finished_at if sync else None,
            )
        )
    return result


@router.get(
    "/feeds",
    response_model=list[FeedStatusOut],
    tags=["zagrożenia"],
    dependencies=[Depends(require("findings:read"))],
)
def feeds_status(session: SessionDep) -> list[FeedStatusOut]:
    return _feed_status(session)


@router.post(
    "/feeds/sync",
    response_model=TaskOut,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["zagrożenia"],
)
def sync_feeds(
    dispatcher: DispatcherDep,
    principal: Annotated[Principal, Depends(require("feeds:sync"))],
) -> TaskOut:
    return TaskOut(
        task_id=dispatcher.sync_feeds(principal.actor),
        detail="Synchronizacja feedów zlecona workerowi",
    )


@router.get(
    "/review-queue",
    response_model=list[ReviewItemOut],
    tags=["weryfikacja"],
    dependencies=[Depends(require("review:read"))],
)
def review_queue(session: SessionDep) -> list[ReviewItemOut]:
    rows = session.execute(
        select(MatchCandidate, Software, Asset)
        .join(Software, MatchCandidate.software_id == Software.id)
        .join(Asset, Software.asset_id == Asset.id)
        .where(MatchCandidate.decision == "pending")
        .order_by(Asset.name, Software.port, MatchCandidate.score.desc())
    ).all()
    return [
        ReviewItemOut(
            id=candidate.id,
            cpe=candidate.cpe,
            score=candidate.score,
            method=candidate.method,
            reason=candidate.reason,
            created_at=candidate.created_at,
            software=SoftwareOut.model_validate(software),
            asset=AssetRef.model_validate(asset),
        )
        for candidate, software, asset in rows
    ]


@router.post(
    "/review-queue/{candidate_id}/decision",
    response_model=ReviewDecisionOut,
    tags=["weryfikacja"],
)
def decide_review(
    candidate_id: uuid.UUID,
    payload: ReviewDecisionIn,
    session: SessionDep,
    rulebook: RulebookDep,
    principal: Annotated[Principal, Depends(require("review:decide"))],
) -> ReviewDecisionOut:
    """Decyzja człowieka. Dopiero po akceptacji powstają findingi dla tego produktu."""
    try:
        software = decide_candidate(
            session, candidate_id, accept=payload.accept, decided_by=principal.username
        )
    except CandidateError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    report = analyze(session, rulebook, channel_sender())
    return ReviewDecisionOut(
        match_status=software.match_status,
        findings_created=len(report.findings.of_kind("created")),
    )


@router.get(
    "/signal-queue",
    response_model=list[SignalItemOut],
    tags=["weryfikacja"],
    dependencies=[Depends(require("review:read"))],
)
def signal_queue(session: SessionDep) -> list[SignalItemOut]:
    """Sygnały KEV bez zakresu wersji, dopasowane do inwentarza po nazwie produktu."""
    rows = session.execute(
        select(SignalMatch, Vulnerability, Software, Asset)
        .join(Vulnerability, SignalMatch.vulnerability_id == Vulnerability.id)
        .join(Software, SignalMatch.software_id == Software.id)
        .join(Asset, Software.asset_id == Asset.id)
        .where(SignalMatch.decision == "pending")
        .order_by(Vulnerability.cve_id, SignalMatch.score.desc())
    ).all()
    return [
        SignalItemOut(
            id=signal.id,
            cve_id=vuln.cve_id,
            source=signal.source,
            vendor=signal.vendor,
            product=signal.product,
            score=signal.score,
            method=signal.method,
            reason=signal.reason,
            kev_due_date=vuln.kev_due_date,
            created_at=signal.created_at,
            software=SoftwareOut.model_validate(software),
            asset=AssetRef.model_validate(asset),
        )
        for signal, vuln, software, asset in rows
    ]


@router.post(
    "/signal-queue/{signal_id}/decision",
    response_model=SignalDecisionOut,
    tags=["weryfikacja"],
)
def decide_signal_endpoint(
    signal_id: uuid.UUID,
    payload: ReviewDecisionIn,
    session: SessionDep,
    rulebook: RulebookDep,
    principal: Annotated[Principal, Depends(require("review:decide"))],
) -> SignalDecisionOut:
    """Decyzja człowieka. Finding (typ `signal`) powstaje tylko po akceptacji."""
    try:
        report = decide_signal(
            session,
            signal_id,
            accept=payload.accept,
            decided_by=principal.username,
            scoring=rulebook.scoring,
        )
    except SignalError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    notify(session, report.changes, rulebook.notifications, channel_sender())
    return SignalDecisionOut(
        decision="confirmed" if payload.accept else "rejected",
        findings_created=len(report.of_kind("created")),
    )


@router.get(
    "/notifications",
    response_model=list[NotificationOut],
    tags=["powiadomienia"],
    dependencies=[Depends(require("notifications:read"))],
)
def list_notifications(session: SessionDep, limit: Limit = 50) -> list[NotificationOut]:
    rows = session.scalars(
        select(Notification).order_by(Notification.created_at.desc()).limit(limit)
    ).all()
    return [NotificationOut.model_validate(r) for r in rows]


@router.post("/assets/import", response_model=AssetImportOut, tags=["inwentarz"])
def import_assets_csv(
    payload: AssetImportIn,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("inventory:write"))],
) -> AssetImportOut:
    """Import CSV (kolumny: name,type,address,exposure,criticality,owner,tags)."""
    rows, errors = parse_assets_csv(payload.csv)
    result = import_assets(session, rows, source="api-csv", actor=principal.actor)
    return AssetImportOut(
        created=result.created, updated=result.updated, unchanged=result.unchanged, errors=errors
    )


@router.get(
    "/assets/{asset_id}/details",
    response_model=AssetDetailOut,
    tags=["inwentarz"],
    dependencies=[Depends(require("inventory:read"))],
)
def asset_details(asset_id: uuid.UUID, session: SessionDep) -> AssetDetailOut:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono zasobu")
    software = session.scalars(
        select(Software).where(Software.asset_id == asset.id).order_by(Software.port)
    ).all()
    history = session.scalars(
        select(AssetHistory)
        .where(AssetHistory.asset_id == asset.id)
        .order_by(AssetHistory.created_at.desc())
        .limit(50)
    ).all()
    active = session.scalar(
        select(func.count())
        .select_from(Finding)
        .where(Finding.asset_id == asset.id, Finding.status.in_(ACTIVE_STATUSES))
    )
    return AssetDetailOut(
        asset=AssetOut.model_validate(asset),
        attributes=asset.attributes or {},
        software=[SoftwareOut.model_validate(s) for s in software],
        history=[AssetHistoryOut.model_validate(h) for h in history],
        active_findings=active or 0,
    )


@router.get(
    "/stats",
    response_model=StatsOut,
    tags=["system"],
    dependencies=[Depends(require("inventory:read"))],
)
def stats(session: SessionDep) -> StatsOut:
    by_status = {
        str(k): int(v)
        for k, v in session.execute(select(Asset.status, func.count()).group_by(Asset.status))
    }
    by_level = {
        str(k): int(v)
        for k, v in session.execute(
            select(Finding.risk_level, func.count())
            .where(Finding.status.in_(ACTIVE_STATUSES))
            .group_by(Finding.risk_level)
        )
    }
    kev_active = session.scalar(
        select(func.count())
        .select_from(Finding)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .where(Finding.status.in_(ACTIVE_STATUSES), Vulnerability.in_kev.is_(True))
    )
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    last_scan = session.scalar(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(1))
    return StatsOut(
        assets_total=sum(by_status.values()),
        assets_by_status=by_status,
        findings_active=sum(by_level.values()),
        findings_by_level=by_level,
        kev_active=kev_active or 0,
        review_queue=session.scalar(
            select(func.count())
            .select_from(MatchCandidate)
            .where(MatchCandidate.decision == "pending")
        )
        or 0,
        awaiting_approval=session.scalar(
            select(func.count())
            .select_from(ScanAction)
            .where(ScanAction.status == "awaiting_approval")
        )
        or 0,
        notifications_today=session.scalar(
            select(func.count())
            .select_from(Notification)
            .where(Notification.created_at >= today, Notification.channel == "in_app")
        )
        or 0,
        last_scan=ScanRunOut.model_validate(last_scan) if last_scan else None,
        feeds=_feed_status(session),
    )
