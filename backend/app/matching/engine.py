"""Matching Engine: oprogramowanie → CPE → podatności → findingi z oceną ryzyka.

Wszystkie decyzje są deterministyczne:

* pewność dopasowania produktu >= próg `auto` tworzy findingi,
* pewność w przedziale [`review`, `auto`) trafia do kolejki weryfikacji i NIE tworzy
  findingów, dopóki człowiek nie potwierdzi dopasowania,
* pakiety dystrybucji dostają mnożnik pewności (możliwe backporty poprawek),
* gdy wersji nie da się porównać z zakresem, finding nie powstaje (nie zgadujemy).
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.inventory.service import UNKNOWN_PRODUCT
from app.matching.cpe import (
    CpeEntry,
    MatchingConfig,
    ProductNormalizer,
    parse_cpe,
)
from app.matching.versions import VersionRange, in_range, is_distro_version
from app.models import (
    Asset,
    CpeProduct,
    Finding,
    FindingEvent,
    MatchCandidate,
    Software,
    VulnAffected,
    Vulnerability,
)
from app.models.base import utcnow
from app.scoring.engine import RiskInputs, ScoringConfig, score_risk

ACTOR = "rule:matching"
ACTIVE_STATUSES = ("open", "acknowledged", "in_progress")
MATCHED_STATUSES = ("auto", "confirmed")


def build_normalizer(session: Session, aliases: dict[str, CpeEntry]) -> ProductNormalizer:
    dictionary = [
        CpeEntry(vendor, product, title)
        for vendor, product, title in session.execute(
            select(CpeProduct.vendor, CpeProduct.product, CpeProduct.title)
        )
    ]
    return ProductNormalizer(aliases, dictionary)


@dataclass
class ProductReport:
    auto: int = 0
    needs_review: int = 0
    unmatched: int = 0


def resolve_products(
    session: Session, normalizer: ProductNormalizer, config: MatchingConfig
) -> ProductReport:
    """Rozstrzyga produkty, które nie mają jeszcze decyzji (`unmatched`)."""
    report = ProductReport()
    decisions: list[dict[str, Any]] = []
    pending = session.scalars(
        select(Software).where(Software.match_status == "unmatched").order_by(Software.first_seen)
    ).all()
    for software in pending:
        if software.product == UNKNOWN_PRODUCT:
            software.match_method = "none"
            report.unmatched += 1
            continue
        resolution = normalizer.resolve(
            software.product,
            vendor=software.vendor,
            tool_cpes=[software.cpe] if software.cpe else [],
        )
        best = resolution.best
        evaluated_before = software.match_method is not None
        distro = is_distro_version(software.version, software.raw_banner)
        penalty = config.distro_penalty if distro else 1.0
        confidence = round(best.score * penalty, 3) if best else 0.0
        software.match_confidence = confidence
        software.match_method = best.method if best else "none"
        if best is not None and confidence >= config.auto:
            software.cpe_vendor, software.cpe_product = best.entry.key
            software.match_status = "auto"
            report.auto += 1
        elif best is not None and confidence >= config.review:
            software.match_status = "needs_review"
            report.needs_review += 1
            known = set(
                session.scalars(
                    select(MatchCandidate.cpe).where(MatchCandidate.software_id == software.id)
                )
            )
            for candidate in resolution.candidates:
                score = round(candidate.score * penalty, 3)
                if score < config.review or candidate.entry.cpe in known:
                    continue
                reason = f"Dopasowanie metodą {candidate.method}, pewność {candidate.score:.2f}"
                if distro:
                    reason += (
                        f" × {config.distro_penalty} (pakiet dystrybucji: "
                        "możliwe backporty poprawek bez zmiany numeru wersji)"
                    )
                session.add(
                    MatchCandidate(
                        software_id=software.id,
                        cpe=candidate.entry.cpe,
                        score=score,
                        method=candidate.method,
                        reason=reason,
                    )
                )
        else:
            report.unmatched += 1
            if evaluated_before:
                continue  # ten sam wynik co poprzednio: bez kolejnego wpisu w dzienniku
        decisions.append(
            {
                "software": f"{software.product} {software.version}".strip(),
                "decision": software.match_status,
                "method": software.match_method,
                "confidence": confidence,
                "cpe": best.entry.cpe if best else None,
            }
        )
    session.flush()
    if decisions:
        audit.record(
            session,
            audit.AuditEvent(
                actor=ACTOR,
                action="products_matched",
                reason=(
                    f"Progi: automatycznie od {config.auto}, do weryfikacji od {config.review}, "
                    f"mnożnik dla pakietów dystrybucji {config.distro_penalty}"
                ),
                inputs={
                    "auto": report.auto,
                    "needs_review": report.needs_review,
                    "unmatched": report.unmatched,
                    "decisions": decisions[:100],
                },
                object_type="software",
            ),
        )
    return report


class CandidateError(Exception):
    """Decyzji nie da się zapisać (brak kandydata albo już rozstrzygnięty)."""


def decide_candidate(
    session: Session, candidate_id: uuid.UUID, *, accept: bool, decided_by: str
) -> Software:
    """Decyzja człowieka z kolejki weryfikacji. Findingi powstają dopiero po akceptacji."""
    candidate = session.get(MatchCandidate, candidate_id)
    if candidate is None:
        raise CandidateError("Nie znaleziono kandydata")
    if candidate.decision != "pending":
        raise CandidateError("Ten kandydat został już rozstrzygnięty")
    software = session.get(Software, candidate.software_id)
    if software is None:
        raise CandidateError("Oprogramowanie już nie istnieje")
    now = utcnow()
    candidate.decision = "accepted" if accept else "rejected"
    candidate.decided_by = decided_by
    candidate.decided_at = now
    others = session.scalars(
        select(MatchCandidate).where(
            MatchCandidate.software_id == software.id,
            MatchCandidate.decision == "pending",
            MatchCandidate.id != candidate.id,
        )
    ).all()
    if accept:
        parsed = parse_cpe(candidate.cpe)
        if parsed is None:
            raise CandidateError("Kandydat ma nieprawidłowy identyfikator CPE")
        software.cpe_vendor, software.cpe_product = parsed[0], parsed[1]
        software.match_status = "confirmed"
        for other in others:
            other.decision = "rejected"
            other.decided_by = decided_by
            other.decided_at = now
    elif not others:
        software.match_status = "rejected"
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=f"user:{decided_by}",
            action="match_confirmed" if accept else "match_rejected",
            reason="Decyzja człowieka w kolejce weryfikacji dopasowań",
            inputs={
                "software": f"{software.product} {software.version}".strip(),
                "cpe": candidate.cpe,
                "score": candidate.score,
                "method": candidate.method,
            },
            object_type="software",
            object_id=str(software.id),
        ),
    )
    return software


@dataclass(frozen=True)
class FindingChange:
    finding: Finding
    kind: str  # created | rescored | reopened | resolved
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)


@dataclass
class MatchReport:
    changes: list[FindingChange] = field(default_factory=list)
    matched: int = 0
    undetermined: int = 0

    def of_kind(self, kind: str) -> list[FindingChange]:
        return [c for c in self.changes if c.kind == kind]


def _rescore_reason(before: dict[str, Any], after: dict[str, Any]) -> str:
    old = {c["name"]: c for c in before.get("components", [])}
    parts = [
        f"{c['label']}: {old[c['name']]['source']} → {c['source']}"
        for c in after.get("components", [])
        if c["name"] in old and old[c["name"]]["source"] != c["source"]
    ]
    if before.get("config_version") != after.get("config_version"):
        parts.append("zmiana konfiguracji formuły")
    return "; ".join(parts) or "zmiana danych wejściowych"


def _state(finding: Finding) -> dict[str, Any]:
    return {"status": finding.status, "score": finding.risk_score, "level": finding.risk_level}


def evaluate_findings(session: Session, scoring: ScoringConfig) -> MatchReport:
    """Przelicza findingi CVE dla całego inwentarza. Idempotentne: ponowne uruchomienie
    na tych samych danych nie tworzy duplikatów ani zdarzeń."""
    now = utcnow()
    report = MatchReport()
    affected_by_product: dict[tuple[str, str], list[tuple[VulnAffected, Vulnerability]]]
    affected_by_product = defaultdict(list)
    for affected, vuln in session.execute(
        select(VulnAffected, Vulnerability)
        .join(Vulnerability, VulnAffected.vulnerability_id == Vulnerability.id)
        .order_by(Vulnerability.cve_id)
    ):
        affected_by_product[(affected.cpe_vendor, affected.cpe_product)].append((affected, vuln))

    existing = {
        f.dedup_key: f for f in session.scalars(select(Finding).where(Finding.type == "cve"))
    }
    still_valid: set[str] = set()

    rows = session.execute(
        select(Software, Asset)
        .join(Asset, Software.asset_id == Asset.id)
        .where(Software.match_status.in_(MATCHED_STATUSES))
        .order_by(Asset.name, Software.port)
    ).all()
    for software, asset in rows:
        if not software.cpe_vendor or not software.cpe_product:
            continue
        hits: dict[str, tuple[VulnAffected, Vulnerability]] = {}
        unknown: set[str] = set()
        for affected, vuln in affected_by_product.get(
            (software.cpe_vendor, software.cpe_product), []
        ):
            bounds = VersionRange(
                exact=affected.version_exact,
                start_including=affected.start_including,
                start_excluding=affected.start_excluding,
                end_including=affected.end_including,
                end_excluding=affected.end_excluding,
            )
            verdict = in_range(software.version, bounds)
            if verdict is True:
                hits.setdefault(vuln.cve_id, (affected, vuln))
            elif verdict is None:
                unknown.add(vuln.cve_id)
        report.undetermined += len(unknown - set(hits))

        for cve_id, (affected, vuln) in hits.items():
            report.matched += 1
            key = (
                f"cve:{asset.id}:{cve_id}:{software.cpe_vendor}:{software.cpe_product}"
                f":{software.port or 0}"
            )
            still_valid.add(key)
            bounds = VersionRange(
                exact=affected.version_exact,
                start_including=affected.start_including,
                start_excluding=affected.start_excluding,
                end_including=affected.end_including,
                end_excluding=affected.end_excluding,
            )
            risk = score_risk(
                RiskInputs(
                    exposure=asset.exposure,
                    criticality=asset.criticality,
                    cvss=vuln.cvss_score,
                    epss=vuln.epss,
                    in_kev=vuln.in_kev,
                    has_public_exploit=vuln.has_public_exploit,
                ),
                scoring,
            )
            evidence = {
                "cve_id": cve_id,
                "product": software.product,
                "version": software.version,
                "port": software.port,
                "protocol": software.protocol,
                "banner": software.raw_banner,
                "cpe": f"cpe:2.3:a:{software.cpe_vendor}:{software.cpe_product}",
                "match_method": software.match_method,
                "match_status": software.match_status,
                "match_confidence": software.match_confidence,
                "affected_range": bounds.describe(),
                "fixed_version": affected.fixed_version,
                "source": software.source,
            }
            finding = existing.get(key)
            if finding is None:
                finding = Finding(
                    asset_id=asset.id,
                    software_id=software.id,
                    vulnerability_id=vuln.id,
                    type="cve",
                    dedup_key=key,
                    risk_score=risk.score,
                    risk_level=risk.level,
                    risk_breakdown=risk.breakdown,
                    evidence=evidence,
                    first_seen=now,
                    last_seen=now,
                )
                session.add(finding)
                session.flush()
                existing[key] = finding
                change = FindingChange(finding, "created", after=_state(finding))
                _record_change(
                    session,
                    change,
                    f"{software.product} {software.version} w zakresie podatnych wersji "
                    f"({bounds.describe()}). {risk.breakdown['summary']}",
                )
                report.changes.append(change)
                continue

            before = _state(finding)
            old_breakdown = finding.risk_breakdown
            finding.software_id = software.id
            finding.last_seen = now
            finding.evidence = evidence
            reopened = finding.status == "resolved"
            if reopened:
                finding.status = "open"
            rescored = abs(finding.risk_score - risk.score) >= 0.05
            finding.risk_score = risk.score
            finding.risk_level = risk.level
            finding.risk_breakdown = risk.breakdown
            if reopened:
                change = FindingChange(finding, "reopened", before, _state(finding))
                _record_change(session, change, "Podatna wersja została ponownie wykryta")
                report.changes.append(change)
            elif rescored:
                change = FindingChange(finding, "rescored", before, _state(finding))
                _record_change(session, change, _rescore_reason(old_breakdown, risk.breakdown))
                report.changes.append(change)

    for key, finding in existing.items():
        if key in still_valid or finding.status not in ACTIVE_STATUSES:
            continue
        before = _state(finding)
        finding.status = "resolved"
        change = FindingChange(finding, "resolved", before, _state(finding))
        _record_change(
            session, change, "Podatna wersja nie jest już wykrywana na zasobie albo zmienił się CVE"
        )
        report.changes.append(change)
    session.flush()
    return report


def _record_change(session: Session, change: FindingChange, reason: str) -> None:
    finding = change.finding
    session.add(
        FindingEvent(
            finding_id=finding.id,
            kind=change.kind,
            before=change.before,
            after=change.after,
            actor=ACTOR,
            reason=reason,
        )
    )
    audit.record(
        session,
        audit.AuditEvent(
            actor=ACTOR,
            action=f"finding_{change.kind}",
            reason=reason,
            inputs={
                "evidence": finding.evidence,
                "before": change.before,
                "after": change.after,
                "risk_summary": finding.risk_breakdown.get("summary"),
            },
            object_type="finding",
            object_id=str(finding.id),
        ),
    )
