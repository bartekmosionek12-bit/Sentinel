"""Discovery: cele, przebiegi, wyniki, porównanie, import/eksport, DefectDojo."""

from __future__ import annotations

import ipaddress
import uuid
from functools import lru_cache
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import DispatcherDep, ScopeGuardDep, SessionDep
from app.core import audit
from app.core.config import get_settings
from app.core.scope_guard import Intrusiveness, ScopeError
from app.discovery.analysis import (
    OVERRIDE_FIELDS,
    compare,
    diff_rows,
    host_states,
    overrides,
    present,
)
from app.discovery.defectdojo import DojoClient, DojoConfig, DojoError, findings_for
from app.discovery.engine import DiscoveryConfig, parse_targets
from app.discovery.io import ImportError_, hosts_csv, nmap_xml, parse_import, rows_csv
from app.iam.deps import require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models import (
    DefectDojoExport,
    DiscoveryBatch,
    DiscoveryRun,
    Observation,
    ObservationOverride,
)
from app.models.base import utcnow

router = APIRouter(prefix="/api/discovery", tags=["discovery"], route_class=RedactingRoute)

Reader = Annotated[Principal, Depends(require("scan:read"))]
Runner = Annotated[Principal, Depends(require("scan:run"))]
Importer = Annotated[Principal, Depends(require("inventory:write"))]
Editor = Annotated[Principal, Depends(require("findings:update"))]
Exporter = Annotated[Principal, Depends(require("reports:export"))]
DojoExporter = Annotated[Principal, Depends(require("defectdojo:export"))]


@lru_cache
def discovery_config() -> DiscoveryConfig:
    return DiscoveryConfig.from_file(get_settings().rules_dir / "discovery.yaml")


class TargetsIn(BaseModel):
    text: str = Field(default="", max_length=2_000_000)
    items: list[str] = Field(default_factory=list, max_length=100_000)

    def all(self) -> list[str]:
        lines = [line.split("#", 1)[0] for line in self.text.replace(",", "\n").splitlines()]
        return [*self.items, *[line.strip() for line in lines if line.strip()]]


class RunIn(TargetsIn):
    name: str = Field(default="", max_length=200)
    settings: dict[str, Any] = Field(default_factory=dict)


class OverrideIn(BaseModel):
    field: Literal["hostname", "note", "tags", "hidden_flags", "criticality", "status"]
    value: Any = None


class ImportIn(BaseModel):
    content: str = Field(max_length=20_000_000)
    filename: str = Field(default="", max_length=200)
    name: str = Field(default="", max_length=200)


class DojoExportIn(BaseModel):
    run_id: uuid.UUID
    ips: list[str] = Field(default_factory=list, max_length=10_000)


def _run_out(run: DiscoveryRun) -> dict[str, Any]:
    progress = run.addresses_done / run.addresses_total if run.addresses_total else 0
    return {
        "id": str(run.id),
        "name": run.name,
        "status": run.status,
        "source": run.source,
        "targets": run.targets[:50],
        "targets_count": len(run.targets),
        "settings": run.settings,
        "created_by": run.created_by,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "addresses_total": run.addresses_total,
        "addresses_done": run.addresses_done,
        "progress": round(progress, 4),
        "batches_done": run.batches_done,
        "hosts_up": run.hosts_up,
        "eta_seconds": run.eta_seconds,
        "duration_seconds": run.duration_seconds,
        "error": run.error,
        "summary": run.summary,
    }


def _get_run(session: SessionDep, run_id: uuid.UUID) -> DiscoveryRun:
    run = session.get(DiscoveryRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiego przebiegu")
    return run


@router.get("/settings")
def get_discovery_settings(principal: Reader) -> dict[str, Any]:
    config = discovery_config()
    defaults = config.settings()
    return {
        "defaults": {**defaults.__dict__, "http_paths": list(defaults.http_paths)},
        "limits": config.limits,
        "host_state": {"inactive_after_runs": config.inactive_after_runs, "window": config.window},
    }


@router.post("/targets/preview")
def preview_targets(payload: TargetsIn, guard: ScopeGuardDep, principal: Reader) -> dict[str, Any]:
    """Walidacja i podgląd celów przed uruchomieniem: liczba adresów, błędy, zgodność z zakresem."""
    parsed = parse_targets(payload.all())
    limit = discovery_config().limits.get("addresses", 70000)
    rows = []
    for network in parsed.networks[:200]:
        target = str(network)
        try:
            if network.num_addresses == 1:
                guard.authorize(
                    str(network.network_address),
                    tool="nmap",
                    intrusiveness=Intrusiveness.LIGHT,
                    rule_name="discovery_preview",
                    dry_run=True,
                )
            else:
                ipaddress.ip_network(target)
                guard.authorize_network(
                    str(network)
                    if network.num_addresses <= 4096
                    else str(
                        next(
                            network.subnets(
                                new_prefix=max(network.prefixlen, network.max_prefixlen - 12)
                            )
                        )
                    ),
                    tool="nmap",
                    intrusiveness=Intrusiveness.LIGHT,
                    rule_name="discovery_preview",
                    dry_run=True,
                )
            allowed, reason = True, "w zakresie"
        except ScopeError as error:
            allowed, reason = False, error.reason
        rows.append(
            {
                "target": target,
                "addresses": network.num_addresses,
                "allowed": allowed,
                "reason": reason,
            }
        )
    for domain in parsed.domains[:200]:
        try:
            guard.authorize(
                domain,
                tool="nmap",
                intrusiveness=Intrusiveness.LIGHT,
                rule_name="discovery_preview",
                dry_run=True,
            )
            allowed, reason = True, "w zakresie"
        except ScopeError as error:
            allowed, reason = False, error.reason
        rows.append({"target": domain, "addresses": 1, "allowed": allowed, "reason": reason})
    errors = list(parsed.errors)
    if parsed.addresses > limit:
        errors.append(f"Za dużo adresów w jednym przebiegu: {parsed.addresses} (limit {limit})")
    return {
        "addresses": parsed.addresses,
        "networks": len(parsed.networks),
        "domains": len(parsed.domains),
        "rows": rows,
        "errors": errors,
        "ok": bool(parsed.networks or parsed.domains)
        and not errors
        and all(r["allowed"] for r in rows),
    }


@router.post("/runs", status_code=status.HTTP_202_ACCEPTED)
def create_run(
    payload: RunIn, session: SessionDep, dispatcher: DispatcherDep, principal: Runner
) -> dict[str, Any]:
    parsed = parse_targets(payload.all())
    if parsed.errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "; ".join(parsed.errors[:5]))
    if not parsed.networks and not parsed.domains:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Podaj co najmniej jeden cel")
    limit = discovery_config().limits.get("addresses", 70000)
    if parsed.addresses > limit:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"Za dużo adresów ({parsed.addresses}, limit {limit})",
        )
    settings = discovery_config().settings(payload.settings)
    run = DiscoveryRun(
        name=payload.name or f"Przebieg {utcnow():%Y-%m-%d %H:%M}",
        targets=[*map(str, parsed.networks), *parsed.domains],
        settings={**settings.__dict__, "http_paths": list(settings.http_paths)},
        created_by=principal.actor,
        addresses_total=parsed.addresses,
    )
    session.add(run)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="discovery_requested",
            reason="Zlecono przebieg discovery",
            inputs={
                "targets": run.targets[:50],
                "addresses": parsed.addresses,
                "settings": run.settings,
            },
            object_type="discovery_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    dispatcher.run_discovery(run.id)
    return _run_out(run)


@router.get("/runs")
def list_runs(
    session: SessionDep, principal: Reader, limit: Annotated[int, Query(ge=1, le=200)] = 30
) -> list[dict[str, Any]]:
    runs = session.scalars(
        select(DiscoveryRun).order_by(DiscoveryRun.created_at.desc()).limit(limit)
    )
    return [_run_out(run) for run in runs]


@router.get("/runs/{run_id}")
def get_run(run_id: uuid.UUID, session: SessionDep, principal: Reader) -> dict[str, Any]:
    run = _get_run(session, run_id)
    batches = session.scalars(
        select(DiscoveryBatch)
        .where(DiscoveryBatch.run_id == run.id)
        .order_by(DiscoveryBatch.finished_at.desc())
        .limit(200)
    )
    return {
        **_run_out(run),
        "batches": [
            {
                "target": b.target,
                "addresses": b.addresses,
                "phase": b.phase,
                "status": b.status,
                "hosts_up": b.hosts_up,
                "duration_ms": b.duration_ms,
                "detail": b.detail,
                "finished_at": b.finished_at,
            }
            for b in batches
        ],
    }


@router.post("/runs/{run_id}/stop")
def stop_run(run_id: uuid.UUID, session: SessionDep, principal: Runner) -> dict[str, Any]:
    run = _get_run(session, run_id)
    if run.status in ("queued", "running"):
        run.status = "stopping" if run.status == "running" else "stopped"
        audit.record(
            session,
            audit.AuditEvent(
                actor=principal.actor,
                action="discovery_stopped",
                reason="Zatrzymano przebieg",
                inputs={},
                object_type="discovery_run",
                object_id=str(run.id),
            ),
        )
        session.commit()
    return _run_out(run)


def _hosts(session: SessionDep, run: DiscoveryRun) -> list[dict[str, Any]]:
    config = discovery_config()
    states = host_states(session, inactive_after=config.inactive_after_runs, window=config.window)
    edits = overrides(session)
    observations = session.scalars(select(Observation).where(Observation.run_id == run.id))
    return [present(o, edits.get(o.ip), states.get(o.ip)) for o in observations]


@router.get("/runs/{run_id}/hosts")
def run_hosts(run_id: uuid.UUID, session: SessionDep, principal: Reader) -> list[dict[str, Any]]:
    return _hosts(session, _get_run(session, run_id))


@router.get("/runs/{run_id}/export")
def export_run(
    run_id: uuid.UUID,
    session: SessionDep,
    principal: Exporter,
    format: Annotated[Literal["json", "csv", "nmap"], Query()] = "json",
) -> Response:
    run = _get_run(session, run_id)
    hosts = _hosts(session, run)
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="discovery_exported",
            reason=f"Eksport {format}",
            inputs={"hosts": len(hosts)},
            object_type="discovery_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    name = f"sentinel-discovery-{run.id.hex[:8]}"
    if format == "csv":
        return Response(
            hosts_csv(hosts),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{name}.csv"'},
        )
    if format == "nmap":
        return Response(
            nmap_xml(hosts),
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="{name}.xml"'},
        )
    import json

    body = json.dumps(
        {"run": _run_out(run), "hosts": hosts}, default=str, ensure_ascii=False, indent=2
    )
    return Response(
        body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}.json"'},
    )


@router.get("/compare")
def compare_runs(
    older: uuid.UUID, newer: uuid.UUID, session: SessionDep, principal: Reader
) -> dict[str, Any]:
    try:
        return compare(session, older, newer)
    except LookupError as error:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error


@router.get("/compare/export")
def export_compare(
    older: uuid.UUID,
    newer: uuid.UUID,
    session: SessionDep,
    principal: Exporter,
    format: Annotated[Literal["json", "csv"], Query()] = "json",
) -> Response:
    try:
        diff = compare(session, older, newer)
    except LookupError as error:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
    if format == "csv":
        return Response(
            rows_csv(diff_rows(diff)),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="sentinel-roznice.csv"'},
        )
    import json

    return Response(
        json.dumps(diff, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="sentinel-roznice.json"'},
    )


@router.get("/states")
def states(session: SessionDep, principal: Reader) -> dict[str, Any]:
    config = discovery_config()
    data = host_states(session, inactive_after=config.inactive_after_runs, window=config.window)
    counts: dict[str, int] = {}
    for item in data.values():
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    return {"counts": counts, "hosts": data}


@router.put("/overrides/{ip}")
def set_override(
    ip: str, payload: OverrideIn, session: SessionDep, principal: Editor
) -> dict[str, Any]:
    """Ręczna zmiana wyniku. Zapisana osobno, więc kolejny skan jej nie nadpisze."""
    if payload.field not in OVERRIDE_FIELDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Tego pola nie można zmienić")
    row = session.scalar(
        select(ObservationOverride).where(
            ObservationOverride.ip == ip, ObservationOverride.field == payload.field
        )
    )
    before = row.value if row else None
    if payload.value in (None, "", []):
        if row:
            session.delete(row)
    else:
        if row is None:
            row = ObservationOverride(ip=ip[:64], field=payload.field, updated_by=principal.actor)
            session.add(row)
        row.value = payload.value
        row.updated_by = principal.actor
        row.updated_at = utcnow()
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="observation_edited",
            reason=f"Ręczna zmiana pola {payload.field}",
            inputs={"before": before, "after": payload.value},
            object_type="host",
            object_id=ip[:64],
        ),
    )
    session.commit()
    return overrides(session).get(ip, {})


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_results(payload: ImportIn, session: SessionDep, principal: Importer) -> dict[str, Any]:
    """Import wyników z innych narzędzi (JSON, CSV, nmap XML) jako przebieg `import`."""
    try:
        hosts = parse_import(payload.content, payload.filename)
    except ImportError_ as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    valid = []
    for host in hosts:
        try:
            ipaddress.ip_address(host["ip"])
        except ValueError:
            continue
        valid.append(host)
    if not valid:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Plik nie zawiera żadnego hosta z poprawnym adresem IP",
        )
    from app.discovery.fingerprint import flags_for

    run = DiscoveryRun(
        name=payload.name or f"Import {payload.filename or ''}".strip(),
        status="done",
        source="import",
        targets=sorted({h["ip"] for h in valid}),
        created_by=principal.actor,
        started_at=utcnow(),
        finished_at=utcnow(),
        addresses_total=len(valid),
        addresses_done=len(valid),
        hosts_up=len(valid),
        duration_seconds=0,
        summary={"imported_from": payload.filename or "plik"},
    )
    session.add(run)
    session.flush()
    for host in {h["ip"]: h for h in valid}.values():
        session.add(
            Observation(
                run_id=run.id,
                ip=host["ip"],
                hostname=host.get("hostname"),
                services=host.get("services", []),
                http=host.get("http", []),
                flags=flags_for(host.get("hostname"), host.get("http", [])),
            )
        )
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="discovery_imported",
            reason="Import wyników",
            inputs={"hosts": len(valid), "file": payload.filename},
            object_type="discovery_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    return _run_out(run)


@router.get("/defectdojo/status")
def dojo_status(session: SessionDep, principal: Reader) -> dict[str, Any]:
    exported = session.scalar(select(func.count()).select_from(DefectDojoExport)) or 0
    last = session.scalar(select(func.max(DefectDojoExport.exported_at)))
    return {**DojoClient(DojoConfig.from_env()).status(), "exported": exported, "last_export": last}


@router.post("/defectdojo/export")
def dojo_export(
    payload: DojoExportIn, session: SessionDep, principal: DojoExporter
) -> dict[str, Any]:
    """Zaznaczone obserwacje (albo cały przebieg) jako findingi Info, bez duplikatów."""
    run = _get_run(session, payload.run_id)
    hosts = _hosts(session, run)
    if payload.ips:
        wanted = set(payload.ips)
        hosts = [h for h in hosts if h["ip"] in wanted]
    already = set(session.scalars(select(DefectDojoExport.unique_id)))
    findings = [
        f for h in hosts for f in findings_for(h) if f["unique_id_from_tool"] not in already
    ]
    if not findings:
        return {"sent": 0, "skipped_duplicates": len(already), "detail": "Nic nowego do wysłania"}
    try:
        result = DojoClient(DojoConfig.from_env()).import_findings(
            findings, test_title=f"Sentinel ASI: {run.name}"
        )
    except DojoError as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(error)) from error
    for finding in findings:
        session.add(
            DefectDojoExport(
                unique_id=finding["unique_id_from_tool"],
                run_id=run.id,
                remote_id=result.get("test"),
                exported_by=principal.actor,
            )
        )
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="defectdojo_exported",
            reason="Eksport do DefectDojo",
            inputs={"findings": len(findings), **result},
            object_type="discovery_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    return {"sent": len(findings), **result}
