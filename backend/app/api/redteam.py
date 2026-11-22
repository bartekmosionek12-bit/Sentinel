"""Trzy warstwy skanowania podatności i delegacje dostępu (docs/WARSTWY.md).

Warstwy są rozdzielone: każda ma własne uprawnienie, własny endpoint i startuje wyłącznie
z jawnego wywołania człowieka. Nic tu nie uruchamia kolejnej warstwy samo:
* warstwa 1 `POST /api/redteam/layer1/runs` (`redteam:layer1`),
* warstwa 2 `POST /api/redteam/runs/{id}/analysis` (`redteam:layer2`),
* warstwa 3 to zadania agenta `POST /api/agent/tasks` (`redteam:layer3`).

Uprawnienia warstw ma z roli tylko administrator. Innym daje je delegacja w IAM
(`/api/iam/delegations`): osoba × warstwa × podsieci × okno czasu; endpoint sprawdza, czy
cele mieszczą się w podsieciach delegacji. Odczyt wyników: `findings:read`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import DispatcherDep, ScopeGuardDep, SessionDep
from app.core import audit
from app.core.scope_guard import ScopeGuard
from app.discovery.defectdojo import DojoClient, DojoConfig, DojoError
from app.iam import delegation
from app.iam.deps import AuditSinkDep, authenticated, deny, get_role_catalog, require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models import (
    AgentCapability,
    AgentSwitch,
    DefectDojoExport,
    LayerDelegation,
    RedteamAnalysis,
    RedteamFinding,
    RedteamRun,
    User,
)
from app.redteam.analysis import mitigation_texts
from app.redteam.engine import expand_targets
from app.redteam.groups import dojo_findings, group_findings

router = APIRouter(prefix="/api/redteam", tags=["warstwy"], route_class=RedactingRoute)
iam_router = APIRouter(prefix="/api/iam", tags=["role"], route_class=RedactingRoute)

Reader = Annotated[Principal, Depends(require("findings:read"))]
Layer1 = Annotated[Principal, Depends(require("redteam:layer1"))]
Layer2 = Annotated[Principal, Depends(require("redteam:layer2"))]
DojoExporter = Annotated[Principal, Depends(require("defectdojo:export"))]
IamReader = Annotated[Principal, Depends(require("iam:read"))]
IamManager = Annotated[Principal, Depends(require("iam:manage"))]
Anyone = Annotated[Principal, Depends(authenticated())]

LAYERS: list[dict[str, Any]] = [
    {
        "layer": 1,
        "name": "Skan deterministyczny",
        "description": "nmap -sV i bezpieczne skrypty NSE: TLS, certyfikaty, SSH, SMB, FTP, "
        "metody i nagłówki HTTP, wystawione bazy i przestarzałe wersje. Te same cele dają "
        "ten sam wynik. Wynik na dashboardzie i w DefectDojo.",
        "permission": "redteam:layer1",
        "trigger": "Przycisk „Uruchom warstwę 1”. Bez harmonogramu i bez automatów.",
        "uses_model": False,
    },
    {
        "layer": 2,
        "name": "Analiza LLM",
        "description": "Lokalny model czyta zapisane logi i wyniki warstwy 1 (zanonimizowane) "
        "i daje ocenę ryzyka, kroki naprawy i kolejność działań. Niczego nie skanuje.",
        "permission": "redteam:layer2",
        "trigger": "Przycisk „Analizuj (warstwa 2)” przy przebiegu warstwy 1.",
        "uses_model": True,
    },
    {
        "layer": 3,
        "name": "Autonomiczny agent AI",
        "description": "Agent sam planuje sprawdzenia podatności w granicach zdolności nadanych "
        "przez administratora; każdy krok L2+ zatwierdza człowiek, kill switch zatrzymuje "
        "wszystko.",
        "permission": "redteam:layer3",
        "trigger": "Polecenie dla agenta w zakładce Agent AI.",
        "uses_model": True,
    },
]


# --- schematy --------------------------------------------------------------------


class Layer1In(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=50)
    reason: str = Field(min_length=3, max_length=2000)


class AnalysisIn(BaseModel):
    reason: str = Field(default="", max_length=2000)


class DelegationIn(BaseModel):
    user_id: uuid.UUID
    layer: int = Field(ge=1, le=3)
    scope: list[str] = Field(min_length=1, max_length=20)
    valid_from: datetime
    valid_until: datetime
    reason: str = Field(min_length=3, max_length=2000)


class ReasonIn(BaseModel):
    reason: str = Field(default="", max_length=2000)


# --- pomocnicze ------------------------------------------------------------------


def _in_scan_scope(guard: ScopeGuard, cidr: str) -> bool:
    from ipaddress import ip_network

    network = ip_network(cidr, strict=False)
    return any(
        network.version == allowed.version and network.subnet_of(allowed)  # type: ignore[arg-type]
        for allowed in guard.config.allowed_cidrs
    )


def _access_out(item: delegation.LayerAccess) -> dict[str, Any]:
    return {
        "allowed": item.allowed,
        "via": item.via,
        "scope": list(item.scope) if item.scope is not None else None,
        "until": item.until,
    }


def _check_targets(
    session: SessionDep,
    principal: Principal,
    layer: int,
    targets: list[str],
    request: Request,
    sink: AuditSinkDep,
) -> delegation.LayerAccess:
    """Cele muszą leżeć w podsieciach delegacji (administrator: cały zakres skanowania)."""
    access = delegation.access(session, get_role_catalog(), principal, layer)
    if not access.allowed:
        deny(principal, delegation.LAYERS[layer], request, sink)
    outside = delegation.covers(access.scope, targets)
    if outside:
        deny(
            principal,
            f"{delegation.LAYERS[layer]} poza podsiecią delegacji ({', '.join(outside[:5])})",
            request,
            sink,
        )
    return access


def _run(session: SessionDep, run_id: uuid.UUID) -> RedteamRun:
    run = session.get(RedteamRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiego przebiegu warstwy 1")
    return run


def _groups(session: SessionDep, run: RedteamRun) -> list[dict[str, Any]]:
    return group_findings(
        session.scalars(select(RedteamFinding).where(RedteamFinding.run_id == run.id))
    )


def _run_out(run: RedteamRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "status": run.status,
        "targets": list(run.targets),
        "reason": run.reason,
        "requested_by": run.requested_by,
        "via_delegation": run.delegation_id is not None,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "hosts": run.hosts,
        "summary": run.summary or {},
        "error": run.error,
    }


def _analysis_out(row: RedteamAnalysis | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": row.id,
        "status": row.status,
        "source": row.source,
        "model": row.model,
        "requested_by": row.requested_by,
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "content": row.content or {},
        "error": row.error,
    }


def _latest_analysis(session: SessionDep, run_id: uuid.UUID) -> RedteamAnalysis | None:
    return session.scalar(
        select(RedteamAnalysis)
        .where(RedteamAnalysis.run_id == run_id)
        .order_by(RedteamAnalysis.created_at.desc())
        .limit(1)
    )


# --- warstwy i dostęp ------------------------------------------------------------------


@router.get("/layers")
def layers(session: SessionDep, principal: Anyone) -> list[dict[str, Any]]:
    """Opis trzech warstw i dostęp wywołującego (z roli albo z delegacji)."""
    catalog = get_role_catalog()
    return [
        {
            **item,
            "access": _access_out(delegation.access(session, catalog, principal, item["layer"])),
        }
        for item in LAYERS
    ]


# --- warstwa 1 ----------------------------------------------------------------------


@router.post("/layer1/runs", status_code=status.HTTP_202_ACCEPTED)
def start_layer1(
    payload: Layer1In,
    session: SessionDep,
    guard: ScopeGuardDep,
    dispatcher: DispatcherDep,
    principal: Layer1,
    request: Request,
    sink: AuditSinkDep,
) -> dict[str, Any]:
    """Ręczne wywołanie warstwy 1. Nic innego jej nie uruchamia."""
    networks, errors = expand_targets(payload.targets)
    if errors or not networks:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, errors or ["Brak celów"])
    outside_scope = [n for n in networks if not _in_scan_scope(guard, n)]
    if outside_scope:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            [f"{n}: poza zakresem skanowania (scope_guard)" for n in outside_scope],
        )
    access = _check_targets(session, principal, 1, networks, request, sink)
    held = (
        delegation.delegation_for(session, principal, 1, networks)
        if access.via == "delegacja"
        else None
    )
    run = RedteamRun(
        targets=networks,
        reason=payload.reason.strip(),
        requested_by=principal.actor,
        delegation_id=held.id if held else None,
    )
    session.add(run)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="redteam_layer1_requested",
            reason=payload.reason.strip(),
            inputs={"targets": networks, "via": access.via},
            object_type="redteam_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    job = dispatcher.run_redteam_layer1(run.id)
    return {**_run_out(run), "job_id": job}


@router.get("/runs")
def list_runs(
    session: SessionDep, principal: Reader, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[dict[str, Any]]:
    rows = session.scalars(select(RedteamRun).order_by(RedteamRun.created_at.desc()).limit(limit))
    return [_run_out(r) for r in rows]


@router.get("/latest")
def latest(session: SessionDep, principal: Reader) -> dict[str, Any] | None:
    """Ostatni zakończony przebieg warstwy 1 z grupami (karta na dashboardzie)."""
    run = session.scalar(
        select(RedteamRun)
        .where(RedteamRun.status == "done")
        .order_by(RedteamRun.finished_at.desc())
        .limit(1)
    )
    if run is None:
        return None
    return {**_run_out(run), "groups": _groups(session, run)}


@router.get("/runs/{run_id}")
def get_run(run_id: uuid.UUID, session: SessionDep, principal: Reader) -> dict[str, Any]:
    run = _run(session, run_id)
    return {
        **_run_out(run),
        "groups": _groups(session, run),
        "log": list(run.log or []),
        "analysis": _analysis_out(_latest_analysis(session, run.id)),
    }


# --- warstwa 2 ----------------------------------------------------------------------


@router.post("/runs/{run_id}/analysis", status_code=status.HTTP_202_ACCEPTED)
def request_analysis(
    run_id: uuid.UUID,
    payload: AnalysisIn,
    session: SessionDep,
    dispatcher: DispatcherDep,
    principal: Layer2,
    request: Request,
    sink: AuditSinkDep,
) -> dict[str, Any]:
    """Ręczne wywołanie warstwy 2 dla zakończonego przebiegu warstwy 1."""
    run = _run(session, run_id)
    if run.status != "done":
        raise HTTPException(status.HTTP_409_CONFLICT, "Warstwa 1 jeszcze się nie zakończyła")
    _check_targets(session, principal, 2, list(run.targets), request, sink)
    pending = session.scalar(
        select(RedteamAnalysis).where(
            RedteamAnalysis.run_id == run.id, RedteamAnalysis.status.in_(("queued", "running"))
        )
    )
    if pending is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Analiza tego przebiegu już trwa")
    row = RedteamAnalysis(run_id=run.id, requested_by=principal.actor)
    session.add(row)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="redteam_layer2_requested",
            reason=payload.reason.strip() or "Analiza logów warstwy 1",
            inputs={"run": str(run.id)},
            object_type="redteam_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    job = dispatcher.analyze_redteam(row.id)
    return {**(_analysis_out(row) or {}), "job_id": job}


@router.get("/runs/{run_id}/analysis")
def get_analysis(
    run_id: uuid.UUID, session: SessionDep, principal: Reader
) -> dict[str, Any] | None:
    _run(session, run_id)
    return _analysis_out(_latest_analysis(session, run_id))


# --- DefectDojo -----------------------------------------------------------------------


@router.post("/runs/{run_id}/defectdojo")
def export_to_dojo(
    run_id: uuid.UUID, session: SessionDep, principal: DojoExporter
) -> dict[str, Any]:
    """Zgrupowane podatności warstwy 1 do lokalnego DefectDojo: jeden finding na grupę."""
    run = _run(session, run_id)
    if run.status != "done":
        raise HTTPException(status.HTTP_409_CONFLICT, "Warstwa 1 jeszcze się nie zakończyła")
    groups = _groups(session, run)
    analysis = _latest_analysis(session, run.id)
    mitigations = (
        mitigation_texts(analysis.content) if analysis and analysis.status == "done" else None
    )
    already = set(session.scalars(select(DefectDojoExport.unique_id)))
    findings = [
        f
        for f in dojo_findings(run, groups, mitigations)
        if f["unique_id_from_tool"] not in already
    ]
    if not findings:
        return {"sent": 0, "groups": len(groups), "detail": "Nic nowego do wysłania"}
    config = DojoConfig.from_env()
    config = DojoConfig(
        url=config.url,
        token=config.token,
        product=config.product,
        product_type=config.product_type,
        engagement="Red team: warstwa 1",
    )
    try:
        result = DojoClient(config).import_findings(
            findings, test_title=f"Sentinel ASI warstwa 1: {run.created_at:%Y-%m-%d %H:%M}"
        )
    except DojoError as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(error)) from error
    for finding in findings:
        session.add(
            DefectDojoExport(
                unique_id=finding["unique_id_from_tool"][:200],
                run_id=None,
                remote_id=result.get("test"),
                exported_by=principal.actor,
            )
        )
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="defectdojo_exported",
            reason="Eksport podatności warstwy 1 do DefectDojo",
            inputs={"groups": len(findings), "with_mitigation": bool(mitigations), **result},
            object_type="redteam_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    return {"sent": len(findings), "groups": len(groups), **result}


# --- IAM: delegacje i tożsamości non-human ------------------------------------------------


def _delegation_out(session: SessionDep, row: LayerDelegation) -> dict[str, Any]:
    user = session.get(User, row.user_id)
    return {
        "id": row.id,
        "user_id": row.user_id,
        "username": user.username if user else "?",
        "display_name": user.display_name if user else "",
        "layer": row.layer,
        "layer_name": delegation.LAYER_NAMES[row.layer],
        "scope": list(row.scope),
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "reason": row.reason,
        "granted_by": row.granted_by,
        "granted_at": row.granted_at,
        "revoked_at": row.revoked_at,
        "revoked_by": row.revoked_by,
        "state": delegation.state(row),
    }


@iam_router.get("/delegations")
def list_delegations(session: SessionDep, principal: IamReader) -> list[dict[str, Any]]:
    rows = session.scalars(select(LayerDelegation).order_by(LayerDelegation.granted_at.desc()))
    return [_delegation_out(session, r) for r in rows]


@iam_router.post("/delegations", status_code=status.HTTP_201_CREATED)
def create_delegation(
    payload: DelegationIn, session: SessionDep, guard: ScopeGuardDep, principal: IamManager
) -> dict[str, Any]:
    user = session.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiego konta")
    try:
        row = delegation.grant(
            session,
            user,
            layer=payload.layer,
            scope=payload.scope,
            valid_from=payload.valid_from,
            valid_until=payload.valid_until,
            reason=payload.reason,
            actor=principal.actor,
            scan_scope=guard.config,
        )
    except delegation.DelegationError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    session.commit()
    return _delegation_out(session, row)


@iam_router.post("/delegations/{delegation_id}/revoke")
def revoke_delegation(
    delegation_id: uuid.UUID, payload: ReasonIn, session: SessionDep, principal: IamManager
) -> dict[str, Any]:
    row = session.get(LayerDelegation, delegation_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiej delegacji")
    try:
        delegation.revoke(session, row, actor=principal.actor)
    except delegation.DelegationError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    session.commit()
    return _delegation_out(session, row)


@iam_router.get("/non-human")
def non_human(session: SessionDep, principal: IamReader) -> dict[str, Any]:
    """Tożsamości techniczne: role z rules/roles.yaml, konta z tokenów i zdolności agenta."""
    catalog = get_role_catalog()
    roles = [
        {
            "name": role.name,
            "description": role.description,
            "kind": role.kind,
            "permissions": sorted(role.permissions),
        }
        for role in catalog.roles.values()
        if role.kind != "human"
    ]
    accounts = [
        {
            "id": u.id,
            "username": u.username,
            "kind": u.kind,
            "roles": list(u.roles or []),
            "last_seen_at": u.last_seen_at,
        }
        for u in session.scalars(select(User).where(User.kind != "human").order_by(User.username))
    ]
    capability = session.scalar(
        select(AgentCapability).where(AgentCapability.active.is_(True)).limit(1)
    )
    switch = session.get(AgentSwitch, 1)
    tasks_by_delegation = session.scalar(
        select(func.count())
        .select_from(LayerDelegation)
        .where(LayerDelegation.layer == 3, LayerDelegation.revoked_at.is_(None))
    )
    return {
        "roles": roles,
        "accounts": accounts,
        "agent": {
            "layer": 3,
            "killed": bool(switch and switch.killed),
            "capability": (
                {
                    "version": capability.version,
                    "tools": list(capability.tools),
                    "targets": list(capability.targets),
                    "max_level": capability.max_level,
                    "windows": list(capability.windows),
                    "max_calls_per_task": capability.max_calls_per_task,
                    "max_calls_per_target": capability.max_calls_per_target,
                    "note": capability.note,
                    "created_by": capability.created_by,
                }
                if capability
                else None
            ),
            "layer3_delegations": int(tasks_by_delegation or 0),
        },
    }
