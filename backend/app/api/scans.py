"""API skanów. API samo nie skanuje: zleca pracę workerowi w sieci z celami."""

from __future__ import annotations

import copy
import csv
import io
import json
import uuid
from typing import Annotated, Any, TypedDict
from xml.etree import ElementTree

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DispatcherDep, RulebookDep, ScopeGuardDep, SessionDep
from app.api.schemas import ApprovalIn, ScanActionOut, ScanRunOut, TaskOut
from app.core.scope_guard import Intrusiveness, ScopeError
from app.iam.deps import AuditSinkDep, ensure, require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.integrations.defectdojo import DefectDojoClient, DefectDojoError
from app.inventory.service import host_asset, record_host_scan
from app.models import ScanAction, ScanResultOverride, ScanRun, ScanTarget
from app.models.base import utcnow
from app.scanners.runner import ToolError
from app.scans.diff import compare_runs
from app.scans.result_io import parse_results
from app.scans.service import ScanActionError, ScanService
from app.scans.targets import parse_targets, validate_target

router = APIRouter(prefix="/api", tags=["skany"], route_class=RedactingRoute)


@router.get("/defectdojo/status", dependencies=[Depends(require("integrations:manage"))])
def defectdojo_status() -> dict[str, object]:
    try:
        client = DefectDojoClient()
        client.validate_profile()
    except DefectDojoError as error:
        return {"connected": False, "detail": str(error)}
    return {"connected": True, "detail": "Lokalne API DefectDojo gotowe"}


class DojoSelection(BaseModel):
    run_id: uuid.UUID
    selected: list[dict[str, str]] = Field(min_length=1, max_length=50)


@router.post("/defectdojo/export", dependencies=[Depends(require("integrations:manage"))])
def export_defectdojo(payload: DojoSelection, session: SessionDep) -> dict[str, object]:
    run = session.get(ScanRun, payload.run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono przebiegu")
    try:
        client = DefectDojoClient()
        client.validate_profile()
        snapshot = _merged_snapshot(session, run)
        created = duplicates = 0
        for selected in payload.selected:
            host = selected.get("host", "")
            kind = selected.get("kind", "")
            flags = snapshot.get(host, {}).get("flags") or []
            flag = next((item for item in flags if item.get("kind") == kind), None)
            if flag is None:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_CONTENT, "Nie znaleziono obserwacji"
                )
            result = client.export_flag(host, flag)
            created += result == "created"
            duplicates += result == "duplicate"
    except DefectDojoError as error:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
    return {"created": created, "duplicates": duplicates}


@router.get("/scan-results/{run_id}/nmap.xml")
def export_nmap_xml(
    run_id: uuid.UUID,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("scan:read"))],
) -> Response:
    if not principal.can("secrets:redacted:view"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Eksport XML wymaga pełnego wglądu")
    run = session.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono przebiegu")
    root = ElementTree.Element("nmaprun", scanner="nmap", version="sentinel-export")
    for ip, info in _merged_snapshot(session, run).items():
        host = ElementTree.SubElement(root, "host")
        ElementTree.SubElement(host, "status", state="up")
        ElementTree.SubElement(host, "address", addr=ip, addrtype="ipv6" if ":" in ip else "ipv4")
        ports = ElementTree.SubElement(host, "ports")
        for raw in info.get("services", []):
            protocol, port, product, version = (str(raw).split(":", 3) + [""] * 4)[:4]
            item = ElementTree.SubElement(ports, "port", protocol=protocol, portid=port)
            ElementTree.SubElement(item, "state", state="open")
            ElementTree.SubElement(item, "service", name=product, product=product, version=version)
    return Response(
        ElementTree.tostring(root, encoding="unicode"),
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=sentinel-nmap.xml"},
    )


class TargetsIn(BaseModel):
    text: str = Field(min_length=1, max_length=2_000_000)
    format: str = Field(pattern="^(manual|csv|json)$")


class TargetItem(TypedDict):
    target: str
    kind: str


class TargetPreview(TypedDict):
    targets: list[TargetItem]
    errors: list[str]


def _target_preview(payload: TargetsIn, guard: ScopeGuardDep) -> TargetPreview:
    try:
        raw = parse_targets(payload.text, payload.format)
    except (ValueError, csv.Error) as error:
        return {"targets": [], "errors": [str(error)]}
    targets: list[TargetItem] = []
    errors: list[str] = []
    for index, value in enumerate(raw, start=1):
        try:
            normalized, kind = validate_target(value, guard)
            targets.append({"target": normalized, "kind": kind})
        except (ValueError, ScopeError) as error:
            errors.append(f"Cel {index}: {error}")
    return {"targets": targets, "errors": errors}


@router.post("/scan-targets/preview", dependencies=[Depends(require("scan:run"))])
def preview_scan_targets(payload: TargetsIn, guard: ScopeGuardDep) -> TargetPreview:
    return _target_preview(payload, guard)


@router.get("/scan-targets", dependencies=[Depends(require("scan:read"))])
def list_scan_targets(session: SessionDep) -> list[dict[str, str]]:
    return [
        {"target": row.target, "kind": row.kind}
        for row in session.scalars(select(ScanTarget).order_by(ScanTarget.target))
    ]


@router.post("/scan-targets", dependencies=[Depends(require("scan:run"))])
def save_scan_targets(
    payload: TargetsIn, guard: ScopeGuardDep, session: SessionDep
) -> dict[str, object]:
    preview = _target_preview(payload, guard)
    added = 0
    for item in preview["targets"]:
        if session.scalar(select(ScanTarget.id).where(ScanTarget.target == item["target"])):
            continue
        session.add(ScanTarget(target=item["target"], kind=item["kind"]))
        added += 1
    session.commit()
    return {**preview, "added": added}


class ResultsIn(BaseModel):
    text: str = Field(min_length=1, max_length=5_000_000)
    format: str = Field(pattern="^(json|csv|xml)$")


@router.post("/scan-results/import", dependencies=[Depends(require("scan:run"))])
def import_scan_results(
    payload: ResultsIn, session: SessionDep, guard: ScopeGuardDep, rulebook: RulebookDep
) -> dict[str, object]:
    try:
        hosts = parse_results(payload.text, payload.format)
    except (ValueError, TypeError, ToolError, csv.Error, json.JSONDecodeError) as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    run = ScanRun(trigger="import", status="done", finished_at=utcnow())
    session.add(run)
    session.flush()
    for host in hosts:
        asset = host_asset(session, host.ip, host.hostname)
        record_host_scan(session, asset, host, run.id)
        asset.attributes = {
            **asset.attributes,
            "last_seen_run": str(run.id),
            "reachability": "unconfirmed",
        }
    run.summary = {
        "hosts_up": len(hosts),
        "source_format": payload.format,
        "snapshot": ScanService(session, guard, rulebook)._snapshot(run.id),
        "duration_seconds": 0,
        "eta_seconds": 0,
    }
    session.commit()
    return {"run_id": str(run.id), "hosts": len(hosts)}


def _merged_snapshot(session: SessionDep, run: ScanRun) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = copy.deepcopy((run.summary or {}).get("snapshot") or {})
    for row in session.scalars(select(ScanResultOverride)):
        if row.host in snapshot:
            snapshot[row.host][row.field] = row.value
            snapshot[row.host]["manually_changed"] = True
    return snapshot


@router.get("/scan-results/{run_id}", dependencies=[Depends(require("scan:read"))])
def read_scan_results(run_id: uuid.UUID, session: SessionDep) -> dict[str, object]:
    run = session.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono przebiegu")
    return {"run_id": str(run.id), "hosts": _merged_snapshot(session, run)}


class OverrideIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    field: str = Field(pattern="^(name|note|state)$")
    value: str = Field(max_length=2000)


@router.post("/scan-results/override", dependencies=[Depends(require("inventory:write"))])
def override_scan_result(payload: OverrideIn, session: SessionDep) -> dict[str, object]:
    row = session.scalar(
        select(ScanResultOverride).where(
            ScanResultOverride.host == payload.host, ScanResultOverride.field == payload.field
        )
    )
    if row is None:
        row = ScanResultOverride(host=payload.host, field=payload.field, value=payload.value)
        session.add(row)
    else:
        row.value = payload.value
        row.updated_at = utcnow()
    session.commit()
    return {"host": payload.host, "field": payload.field, "manually_changed": True}


@router.get("/scan-results/{run_id}/export")
def export_scan_results(
    run_id: uuid.UUID,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("scan:read"))],
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Response:
    run = session.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono przebiegu")
    snapshot = _merged_snapshot(session, run)
    if format == "csv":
        if not principal.can("secrets:redacted:view"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Eksport CSV wymaga pełnego wglądu")
        output = io.StringIO()
        writer = csv.DictWriter(
            output, fieldnames=("ip", "name", "state", "service", "manually_changed")
        )
        writer.writeheader()
        for ip, host in snapshot.items():
            for service in host.get("services", []) or [""]:
                writer.writerow(
                    {
                        "ip": ip,
                        "name": host.get("name", ""),
                        "state": host.get("state", ""),
                        "service": service,
                        "manually_changed": host.get("manually_changed", False),
                    }
                )
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=scan-results.csv"},
        )
    return Response(
        json.dumps({"hosts": snapshot}, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=scan-results.json"},
    )


@router.get("/scan-diff")
def scan_diff(
    session: SessionDep,
    from_run: uuid.UUID,
    to_run: uuid.UUID,
    principal: Annotated[Principal, Depends(require("scan:read"))],
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Response:
    before = session.get(ScanRun, from_run)
    after = session.get(ScanRun, to_run)
    if before is None or after is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono przebiegu")
    changes = compare_runs(_merged_snapshot(session, before), _merged_snapshot(session, after))
    if format == "csv":
        if not principal.can("secrets:redacted:view"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Eksport CSV wymaga pełnego wglądu")
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=("kind", "host", "item", "before", "after"))
        writer.writeheader()
        writer.writerows(changes)
        return Response(
            output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=scan-diff.csv"},
        )
    return Response(
        json.dumps(changes, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=scan-diff.json"},
    )


# Zatwierdzenie akcji wymaga uprawnienia odpowiadającego jej poziomowi inwazyjności.
_APPROVE_BASE = "scan:approve:l2"
_APPROVE_BY_LEVEL = {
    Intrusiveness.INTRUSIVE: "scan:approve:l2",
    Intrusiveness.REDTEAM: "scan:approve:l3",
}


@router.get("/scans", response_model=list[ScanRunOut], dependencies=[Depends(require("scan:read"))])
def list_scans(
    session: SessionDep, limit: Annotated[int, Query(ge=1, le=100)] = 10
) -> list[ScanRunOut]:
    runs = session.scalars(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)).all()
    result = []
    for run in runs:
        actions = session.scalars(
            select(ScanAction)
            .where(ScanAction.scan_run_id == run.id)
            .order_by(ScanAction.created_at)
        ).all()
        out = ScanRunOut.model_validate(run)
        out.actions = [ScanActionOut.model_validate(a) for a in actions]
        result.append(out)
    return result


@router.post("/scans", response_model=TaskOut, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    dispatcher: DispatcherDep,
    principal: Annotated[Principal, Depends(require("scan:run"))],
) -> TaskOut:
    """Zleca skan zakresu. Co zostanie zeskanowane, wynika z reguł plannera i scope_guard."""
    return TaskOut(
        task_id=dispatcher.run_scan(principal.actor), detail="Skan zlecony workerowi skanów"
    )


@router.get(
    "/scan-actions",
    response_model=list[ScanActionOut],
    dependencies=[Depends(require("scan:read"))],
)
def list_scan_actions(
    session: SessionDep,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[ScanActionOut]:
    query = select(ScanAction)
    if status_filter:
        query = query.where(ScanAction.status == status_filter)
    rows = session.scalars(query.order_by(ScanAction.created_at.desc()).limit(limit)).all()
    return [ScanActionOut.model_validate(r) for r in rows]


def _awaiting(
    session: SessionDep,
    action_id: uuid.UUID,
    principal: Principal,
    request: Request,
    audit: AuditSinkDep,
) -> ScanAction:
    action = session.get(ScanAction, action_id)
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono akcji")
    if action.status != "awaiting_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, "Ta akcja nie czeka na zatwierdzenie")
    level = Intrusiveness(action.intrusiveness)
    permission = _APPROVE_BY_LEVEL.get(level)
    if permission is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Tej akcji nie da się zatwierdzić")
    ensure(principal, permission, request, audit)
    return action


ApproverDep = Annotated[Principal, Depends(require(_APPROVE_BASE))]


@router.post(
    "/scan-actions/{action_id}/approve",
    response_model=TaskOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def approve_scan_action(
    action_id: uuid.UUID,
    payload: ApprovalIn,
    session: SessionDep,
    dispatcher: DispatcherDep,
    principal: ApproverDep,
    request: Request,
    audit: AuditSinkDep,
) -> TaskOut:
    """Zgoda człowieka na akcję inwazyjną (L2 albo L3, zależnie od uprawnień). Akcja i tak
    przejdzie przez scope_guard."""
    _awaiting(session, action_id, principal, request, audit)
    task_id = dispatcher.approve_action(action_id, principal.username, payload.reason)
    return TaskOut(task_id=task_id, detail="Zatwierdzona akcja zlecona workerowi skanów")


@router.post("/scan-actions/{action_id}/reject", response_model=ScanActionOut)
def reject_scan_action(
    action_id: uuid.UUID,
    payload: ApprovalIn,
    session: SessionDep,
    guard: ScopeGuardDep,
    rulebook: RulebookDep,
    principal: ApproverDep,
    request: Request,
    audit: AuditSinkDep,
) -> ScanActionOut:
    _awaiting(session, action_id, principal, request, audit)
    try:
        action = ScanService(session, guard, rulebook).reject(
            action_id, rejected_by=principal.username, reason=payload.reason
        )
    except ScanActionError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    return ScanActionOut.model_validate(action)
