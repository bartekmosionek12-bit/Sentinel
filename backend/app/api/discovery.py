"""Discovery: cele, przebiegi, wyniki, porównanie, import/eksport, DefectDojo."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from functools import lru_cache
from typing import Annotated, Any, Literal

import yaml
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
from app.discovery.report import build_report, report_csv, report_html
from app.discovery.schedule import (
    RunError,
    aware,
    current_window,
    new_run,
    next_start,
    next_window,
    validate_once,
)
from app.discovery.schedule import validate as validate_schedule
from app.discovery.signatures import (
    KINDS,
    MATCH_TYPES,
    MAX_PATHS,
    Observed,
    SignatureError,
    combine,
    evaluate,
    parse_signatures,
)
from app.iam.deps import require
from app.iam.redaction import RedactingRoute
from app.iam.tokens import Principal
from app.models import (
    CustomSignature,
    DefectDojoExport,
    DiscoveryBatch,
    DiscoveryRun,
    DiscoverySchedule,
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
    # Opcjonalny koniec: po nim przebieg kończy rozpoczęte paczki i zapisuje resztę celów.
    end_at: datetime | None = None


class ResumeIn(BaseModel):
    end_at: datetime | None = None


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
        "schedule_id": str(run.schedule_id) if run.schedule_id else None,
        "resume_of": str(run.resume_of) if run.resume_of else None,
        "deadline": run.deadline,
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
                    if network.num_addresses <= 1024
                    else str(
                        next(
                            network.subnets(
                                new_prefix=max(network.prefixlen, network.max_prefixlen - 10)
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
    try:
        if payload.end_at is not None:
            validate_once(utcnow(), payload.end_at, utcnow())
        run = new_run(
            session,
            discovery_config(),
            payload.all(),
            name=payload.name,
            settings=payload.settings,
            actor=principal.actor,
            deadline=payload.end_at,
        )
    except RunError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    session.commit()
    dispatcher.run_discovery(run.id)
    return _run_out(run)


# --- harmonogram ---------------------------------------------------------------------


class ScheduleIn(TargetsIn):
    name: str = Field(min_length=1, max_length=200)
    settings: dict[str, Any] = Field(default_factory=dict)
    interval_minutes: int = Field(default=1440, ge=15, le=60 * 24 * 31)
    window_start: str = "22:00"
    window_end: str = "06:00"
    days: list[int] = Field(default_factory=lambda: list(range(7)), max_length=7)
    timezone: str = Field(default="Europe/Warsaw", max_length=64)
    enabled: bool = True
    # Skan jednorazowy: oba pola razem; wtedy okno, dni i częstotliwość są pomijane.
    start_at: datetime | None = None
    end_at: datetime | None = None


def _schedule_out(session: SessionDep, schedule: DiscoverySchedule) -> dict[str, Any]:
    now = utcnow()
    window = current_window(schedule, now)
    upcoming = next_window(schedule, now)
    last = session.scalar(
        select(DiscoveryRun)
        .where(DiscoveryRun.schedule_id == schedule.id)
        .order_by(DiscoveryRun.created_at.desc())
        .limit(1)
    )
    return {
        "id": str(schedule.id),
        "name": schedule.name,
        "targets": schedule.targets[:5000],
        "targets_count": len(schedule.targets),
        "settings": schedule.settings,
        "interval_minutes": schedule.interval_minutes,
        "window_start": schedule.window_start,
        "window_end": schedule.window_end,
        "days": schedule.days,
        "timezone": schedule.timezone,
        "enabled": schedule.enabled,
        "created_by": schedule.created_by,
        "updated_at": schedule.updated_at,
        "last_started_at": schedule.last_started_at,
        "in_window": window is not None,
        "window_ends_at": window.end if window else None,
        "next_window_at": upcoming.start if upcoming and window is None else None,
        "next_start_at": next_start(schedule, now),
        "resume_pending": schedule.resume_run_id is not None,
        "resume_run_id": str(schedule.resume_run_id) if schedule.resume_run_id else None,
        "once": schedule.once,
        "start_at": aware(schedule.start_at),
        "end_at": aware(schedule.end_at),
        "last_run": _run_out(last) if last else None,
    }


def _apply_schedule(schedule: DiscoverySchedule, payload: ScheduleIn) -> None:
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
    days = sorted(set(payload.days))
    if (payload.start_at is None) != (payload.end_at is None):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Skan jednorazowy wymaga początku i końca"
        )
    try:
        if payload.start_at is not None and payload.end_at is not None:
            validate_once(payload.start_at, payload.end_at, utcnow())
        validate_schedule(
            payload.window_start,
            payload.window_end,
            days,
            payload.timezone,
            payload.interval_minutes,
        )
    except RunError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    resolved = discovery_config().settings(payload.settings)
    schedule.name = payload.name
    schedule.targets = [*map(str, parsed.networks), *parsed.domains]
    schedule.settings = {**resolved.__dict__, "http_paths": list(resolved.http_paths)}
    schedule.interval_minutes = payload.interval_minutes
    schedule.window_start = payload.window_start
    schedule.window_end = payload.window_end
    schedule.days = days
    schedule.timezone = payload.timezone
    schedule.enabled = payload.enabled
    if payload.start_at != aware(schedule.start_at):
        schedule.last_started_at = None  # nowy termin jednorazowego skanu: może ruszyć znowu
    schedule.start_at = payload.start_at
    schedule.end_at = payload.end_at
    schedule.updated_at = utcnow()


def _schedule_audit(
    session: SessionDep, principal: Principal, action: str, reason: str, schedule: DiscoverySchedule
) -> None:
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action=action,
            reason=reason,
            inputs={
                "name": schedule.name,
                "targets": schedule.targets[:5000],
                "interval_minutes": schedule.interval_minutes,
                "window": f"{schedule.window_start}-{schedule.window_end}",
                "days": schedule.days,
                "enabled": schedule.enabled,
            },
            object_type="discovery_schedule",
            object_id=str(schedule.id),
        ),
    )


def _get_schedule(session: SessionDep, schedule_id: uuid.UUID) -> DiscoverySchedule:
    schedule = session.get(DiscoverySchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiego harmonogramu")
    return schedule


@router.get("/schedules")
def list_schedules(session: SessionDep, principal: Reader) -> list[dict[str, Any]]:
    rows = session.scalars(select(DiscoverySchedule).order_by(DiscoverySchedule.created_at))
    return [_schedule_out(session, row) for row in rows]


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_schedule(payload: ScheduleIn, session: SessionDep, principal: Runner) -> dict[str, Any]:
    schedule = DiscoverySchedule(created_by=principal.actor)
    _apply_schedule(schedule, payload)
    session.add(schedule)
    session.flush()
    _schedule_audit(session, principal, "discovery_schedule_created", "Nowy harmonogram", schedule)
    session.commit()
    return _schedule_out(session, schedule)


@router.put("/schedules/{schedule_id}")
def update_schedule(
    schedule_id: uuid.UUID, payload: ScheduleIn, session: SessionDep, principal: Runner
) -> dict[str, Any]:
    schedule = _get_schedule(session, schedule_id)
    _apply_schedule(schedule, payload)
    _schedule_audit(
        session, principal, "discovery_schedule_updated", "Zmieniono harmonogram", schedule
    )
    session.commit()
    return _schedule_out(session, schedule)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(schedule_id: uuid.UUID, session: SessionDep, principal: Runner) -> None:
    schedule = _get_schedule(session, schedule_id)
    _schedule_audit(
        session, principal, "discovery_schedule_deleted", "Usunięto harmonogram", schedule
    )
    session.delete(schedule)
    session.commit()


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
    resumed_by = session.scalar(
        select(DiscoveryRun.id).where(DiscoveryRun.resume_of == run.id).limit(1)
    )
    remaining = run.remaining or {}
    return {
        **_run_out(run),
        "remaining": {
            "networks": len(remaining.get("networks", [])),
            "hosts": len(remaining.get("hosts", [])),
        },
        "resumed_by": str(resumed_by) if resumed_by else None,
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


@router.post("/runs/{run_id}/resume", status_code=status.HTTP_202_ACCEPTED)
def resume_run(
    run_id: uuid.UUID,
    session: SessionDep,
    dispatcher: DispatcherDep,
    principal: Runner,
    payload: ResumeIn | None = None,
) -> dict[str, Any]:
    """Wznawia przebieg wstrzymany na końcu okna: nowy przebieg z zapisaną resztą celów.

    Reszta to niezeskanowane sieci i aktywne hosty bez skanu usług. Każdy cel znowu przechodzi
    przez walidację, limity i scope_guard w silniku, tak jak przy zwykłym przebiegu.
    """
    run = _get_run(session, run_id)
    if run.status != "paused" or not run.remaining:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Wznowić można tylko przebieg wstrzymany z zapisaną resztą"
        )
    already = session.scalar(
        select(DiscoveryRun.id).where(DiscoveryRun.resume_of == run.id).limit(1)
    )
    if already is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Ten przebieg został już wznowiony")
    end_at = payload.end_at if payload else None
    schedule = session.get(DiscoverySchedule, run.schedule_id) if run.schedule_id else None
    rest = [*run.remaining.get("networks", []), *run.remaining.get("hosts", [])]
    try:
        if end_at is not None:
            validate_once(utcnow(), end_at, utcnow())
        resumed = new_run(
            session,
            discovery_config(),
            rest,
            name=f"{run.name.split(' (wznowienie')[0]} (wznowienie {utcnow():%d.%m %H:%M})",
            settings=run.settings,
            actor=principal.actor,
            reason="Ręczne wznowienie wstrzymanego przebiegu",
            schedule=schedule,
            deadline=end_at,
            resume_of=run,
        )
    except RunError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    if schedule is not None and schedule.resume_run_id == run.id:
        schedule.resume_run_id = None
    session.commit()
    dispatcher.run_discovery(resumed.id)
    return _run_out(resumed)


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


@router.get("/runs/{run_id}/report")
def run_report(
    run_id: uuid.UUID,
    session: SessionDep,
    principal: Exporter,
    format: Annotated[Literal["json", "csv", "html"], Query()] = "json",
) -> Response:
    """Raport z przebiegu: podsumowanie, zmiany od poprzedniego, priorytet, flagi, TLS, stany.

    Te same dane w trzech formatach: JSON i CSV (eksport z briefu) oraz HTML do czytania i
    druku do PDF.
    """
    run = _get_run(session, run_id)
    report = build_report(session, run, _hosts(session, run), _run_out(run))
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="discovery_report",
            reason=f"Raport z przebiegu ({format})",
            inputs={"hosts": report["summary"]["hosts"]},
            object_type="discovery_run",
            object_id=str(run.id),
        ),
    )
    session.commit()
    name = f"sentinel-raport-{run.id.hex[:8]}"
    if format == "csv":
        return Response(
            report_csv(report),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{name}.csv"'},
        )
    if format == "html":
        return Response(
            report_html(report),
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{name}.html"'},
        )
    import json

    return Response(
        json.dumps(report, default=str, ensure_ascii=False, indent=2),
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
    if payload.field == "tags" and payload.value not in (None, "", []):
        raw = payload.value.split(",") if isinstance(payload.value, str) else payload.value
        if not isinstance(raw, list) or not all(isinstance(t, str) for t in raw):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Tagi to lista tekstów")
        tags = list(dict.fromkeys(t.strip().lower()[:40] for t in raw if t.strip()))
        if len(tags) > 20:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Najwyżej 20 tagów")
        payload.value = tags or None
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


# --- własne sygnatury detekcyjne (brief R10) ---------------------------------------------


class SignatureIn(BaseModel):
    """Jedna sygnatura w YAML, w tym samym kształcie co pozycja w rules/signatures.yaml."""

    yaml: str = Field(max_length=20_000)


def _signature_definition(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, f"Błędny YAML: {error}"
        ) from error
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    if not isinstance(data, dict):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Podaj jedną sygnaturę (słownik YAML)"
        )
    return data


def _validate_with(
    session: SessionDep, definition: dict[str, Any], replace_id: str | None = None
) -> None:
    builtin = list(discovery_config().builtin_signatures)
    if any(item.get("id") == definition.get("id") for item in builtin):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Ten identyfikator ma sygnatura wbudowana; wybierz inny",
        )
    custom = [
        row.definition
        for row in session.scalars(select(CustomSignature))
        if row.signature_id != replace_id
    ]
    try:
        combine(builtin, [*custom, definition])
    except SignatureError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error


@router.get("/signatures")
def list_signatures(session: SessionDep, principal: Reader) -> dict[str, Any]:
    """Wbudowane (z pliku, tylko odczyt) i własne (z konsoli) sygnatury oraz ich zasady."""
    custom = session.scalars(select(CustomSignature).order_by(CustomSignature.signature_id))
    return {
        "builtin": list(discovery_config().builtin_signatures),
        "custom": [
            {
                "id": row.signature_id,
                "definition": row.definition,
                "updated_by": row.updated_by,
                "updated_at": row.updated_at,
            }
            for row in custom
        ],
        "rules": {
            "kinds": sorted(KINDS),
            "match_types": sorted(MATCH_TYPES),
            "max_paths": MAX_PATHS,
        },
    }


@router.post("/signatures/check")
def check_signature(payload: SignatureIn, session: SessionDep, principal: Runner) -> dict[str, Any]:
    """Walidacja bez zapisu: te same zasady co przy skanie (tylko GET, typy z briefu)."""
    definition = _signature_definition(payload.yaml)
    _validate_with(session, definition, replace_id=str(definition.get("id") or ""))
    return {"ok": True, "definition": definition}


class SignatureTestIn(BaseModel):
    """Sygnatura do sprawdzenia: w YAML z edytora albo po id (wbudowana lub zapisana)."""

    yaml: str | None = Field(default=None, max_length=20_000)
    id: str | None = Field(default=None, max_length=64)
    run_id: uuid.UUID | None = None


# Tych typów nie da się sprawdzić na zapisanych wynikach: treść stron nie jest przechowywana.
LIVE_ONLY = {"html", "generator"}


def _signature_for_test(session: SessionDep, payload: SignatureTestIn) -> dict[str, Any]:
    if payload.yaml:
        return _signature_definition(payload.yaml)
    if payload.id:
        for item in discovery_config().builtin_signatures:
            if item.get("id") == payload.id:
                return dict(item)
        row = session.scalars(
            select(CustomSignature).where(CustomSignature.signature_id == payload.id)
        ).first()
        if row:
            return dict(row.definition)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiej sygnatury")
    raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Podaj yaml albo id sygnatury")


@router.post("/signatures/test")
def test_signature(
    payload: SignatureTestIn, session: SessionDep, principal: Reader
) -> dict[str, Any]:
    """Sprawdza jedną sygnaturę na zapisanych wynikach przebiegu, bez żadnego ruchu sieciowego.

    Nagłówki, ciasteczka, tytuł, hash favicony i kody ścieżek są w wynikach, więc da się je
    dopasować od razu. Fragmentu HTML i meta generatora nie przechowujemy (dane minimalne),
    a wzorzec treści przy ścieżce też wymaga treści: te części sprawdzi dopiero kolejny skan.
    """
    definition = _signature_for_test(session, payload)
    try:
        (signature,) = parse_signatures({"signatures": [definition]})
    except SignatureError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    if payload.run_id:
        run = _get_run(session, payload.run_id)
    else:
        run = session.scalars(
            select(DiscoveryRun)
            .where(DiscoveryRun.status.in_(("done", "stopped", "paused")))
            .order_by(DiscoveryRun.created_at.desc())
        ).first()
        if run is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Brak zakończonego przebiegu")
    offline = tuple(m for m in signature.matches if m.type not in LIVE_ONLY)
    live_only = sorted(
        {m.type for m in signature.matches if m.type in LIVE_ONLY}
        | {"path (wzorzec treści)" for m in signature.matches if m.type == "path" and m.pattern}
    )
    # Wzorzec treści przy ścieżce: na zapisanych danych sprawdzamy tylko kod odpowiedzi.
    relaxed = tuple(
        m if m.type != "path" else type(m)(type=m.type, path=m.path, status=m.status)
        for m in offline
    )
    probe = type(signature)(
        id=signature.id, name=signature.name, kind=signature.kind, matches=relaxed
    )
    hits: list[dict[str, Any]] = []
    services = 0
    observations = session.scalars(select(Observation).where(Observation.run_id == run.id))
    for observation in observations:
        for item in observation.http or []:
            services += 1
            seen = _observed(item)
            for hit in evaluate((probe,), seen) if relaxed else []:
                hits.append(
                    {
                        "ip": observation.ip,
                        "port": item.get("port"),
                        "url": item.get("url"),
                        "title": item.get("title"),
                        "evidence": hit["evidence"],
                        "already_flagged": signature.id
                        in {s.get("id") for s in item.get("signatures") or []},
                    }
                )
    return {
        "signature": {"id": signature.id, "name": signature.name, "kind": signature.kind},
        "run": {"id": str(run.id), "name": run.name, "created_at": run.created_at},
        "services_checked": services,
        "hits": hits,
        "live_only": live_only,
    }


def _observed(item: dict[str, Any]) -> Observed:
    """Zapisany wynik HTTP jako wejście do dopasowania (bez treści stron, których nie mamy)."""
    return Observed(
        headers={str(k).lower(): str(v) for k, v in (item.get("headers") or {}).items()},
        cookies=[str(c.get("name", "")) for c in item.get("cookies") or []],
        body="",
        title=str(item.get("title") or ""),
        generator="",
        favicon_hash=item.get("favicon_hash"),
        paths={str(k): int(v) for k, v in (item.get("paths") or {}).items()},
    )


def _rule_text(match: Any) -> str:
    """Reguła sygnatury po ludzku: czego szuka i w czym."""
    pattern = f"„{match.pattern.pattern}”" if match.pattern is not None else ""
    if match.type == "header":
        return f"nagłówek {match.name}" + (f" pasujący do {pattern}" if pattern else " (obecność)")
    if match.type == "cookie":
        return f"ciasteczko o nazwie pasującej do {pattern}"
    if match.type == "favicon_hash":
        return f"hash favicony równy {match.value}"
    if match.type == "path":
        codes = ", ".join(map(str, match.status))
        body = f", treść pasująca do {pattern}" if pattern else ""
        return f"GET {match.path} zwraca {codes}{body}"
    where = {"html": "fragment HTML", "title": "tytuł strony", "generator": "meta generator"}
    return f"{where[match.type]} pasujący do {pattern}"


@router.get("/signatures/{signature_id}/inspect")
def inspect_signature(signature_id: str, session: SessionDep, principal: Reader) -> dict[str, Any]:
    """Inspekcja jednej sygnatury: reguły po ludzku, trafienia w historii, dowody i
    dopasowanie każdej reguły osobno do ostatniego przebiegu (bez ruchu w sieci).
    """
    builtin = next(
        (dict(i) for i in discovery_config().builtin_signatures if i.get("id") == signature_id),
        None,
    )
    row = None
    if builtin is None:
        row = session.scalars(
            select(CustomSignature).where(CustomSignature.signature_id == signature_id)
        ).first()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiej sygnatury")
    definition = builtin if builtin is not None else dict(row.definition)  # type: ignore[union-attr]
    try:
        (signature,) = parse_signatures({"signatures": [definition]})
    except SignatureError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error

    runs = list(
        session.scalars(
            select(DiscoveryRun)
            .where(DiscoveryRun.status.in_(("done", "stopped", "paused")))
            .order_by(DiscoveryRun.created_at.desc())
            .limit(10)
        )
    )
    history: list[dict[str, Any]] = []
    hosts: list[dict[str, Any]] = []
    rule_hits = [0] * len(signature.matches)
    services_checked = 0
    for index, run in enumerate(runs):
        hit_services, hit_hosts = 0, set()
        for observation in session.scalars(select(Observation).where(Observation.run_id == run.id)):
            for item in observation.http or []:
                found = next(
                    (h for h in item.get("signatures") or [] if h.get("id") == signature.id),
                    None,
                )
                if found:
                    hit_services += 1
                    hit_hosts.add(observation.ip)
                    if index == 0:
                        hosts.append(
                            {
                                "ip": observation.ip,
                                "port": item.get("port"),
                                "url": item.get("url"),
                                "title": item.get("title"),
                                "evidence": found.get("evidence") or [],
                            }
                        )
                if index == 0:
                    services_checked += 1
                    seen = _observed(item)
                    for position, match in enumerate(signature.matches):
                        if match.type in LIVE_ONLY:
                            continue
                        probe = (
                            match
                            if match.type != "path"
                            else type(match)(type=match.type, path=match.path, status=match.status)
                        )
                        single = type(signature)(
                            id=signature.id,
                            name=signature.name,
                            kind=signature.kind,
                            matches=(probe,),
                        )
                        if evaluate((single,), seen):
                            rule_hits[position] += 1
        history.append(
            {
                "run_id": str(run.id),
                "name": run.name,
                "created_at": run.created_at,
                "services": hit_services,
                "hosts": len(hit_hosts),
            }
        )
    latest = runs[0] if runs else None
    return {
        "id": signature.id,
        "name": signature.name,
        "kind": signature.kind,
        "description": signature.description,
        "source": "builtin" if builtin is not None else "custom",
        "updated_by": row.updated_by if row else None,
        "updated_at": row.updated_at if row else None,
        "definition": definition,
        "rules": [
            {
                "type": match.type,
                "text": _rule_text(match),
                "sends_request": match.type == "path",
                "offline": match.type not in LIVE_ONLY,
                "offline_note": (
                    "tylko kod odpowiedzi; treść sprawdza skan"
                    if match.type == "path" and match.pattern is not None
                    else None
                ),
                "latest_run_hits": rule_hits[i] if latest and match.type not in LIVE_ONLY else None,
            }
            for i, match in enumerate(signature.matches)
        ],
        "latest_run": (
            {"id": str(latest.id), "name": latest.name, "created_at": latest.created_at}
            if latest
            else None
        ),
        "services_checked": services_checked,
        "hosts": hosts,
        "history": history,
    }


@router.put("/signatures/{signature_id}")
def save_signature(
    signature_id: str, payload: SignatureIn, session: SessionDep, principal: Runner
) -> dict[str, Any]:
    definition = _signature_definition(payload.yaml)
    if definition.get("id") != signature_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Pole id musi być takie samo jak w adresie"
        )
    _validate_with(session, definition, replace_id=signature_id)
    row = session.scalar(
        select(CustomSignature).where(CustomSignature.signature_id == signature_id)
    )
    before = row.definition if row else None
    if row is None:
        row = CustomSignature(signature_id=signature_id, updated_by=principal.actor)
        session.add(row)
    row.definition = definition
    row.updated_by = principal.actor
    row.updated_at = utcnow()
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="signature_saved",
            reason="Własna sygnatura detekcyjna",
            inputs={"before": before, "after": definition},
            object_type="signature",
            object_id=signature_id,
        ),
    )
    session.commit()
    return {"id": signature_id, "definition": definition}


@router.delete("/signatures/{signature_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_signature(signature_id: str, session: SessionDep, principal: Runner) -> Response:
    row = session.scalar(
        select(CustomSignature).where(CustomSignature.signature_id == signature_id)
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie ma takiej własnej sygnatury")
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="signature_deleted",
            reason="Własna sygnatura detekcyjna",
            inputs={"before": row.definition},
            object_type="signature",
            object_id=signature_id,
        ),
    )
    session.delete(row)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
