"""API organizacji dla konsoli menedżera (#18, #6): działy, urządzenia, ludzie, pokrycie.

Nazwiska widzi tylko ktoś z `personal_data:view`, i tylko gdy nie poprosił o pseudonimy
(`?pseudonyms=true`, przełącznik w konsoli). Każda odpowiedź z nazwiskami zostawia jeden wpis
`personal_data_viewed` w audycie. Warstwa redakcji (RedactingRoute) dodatkowo zamienia nazwiska
na pseudonimy, gdyby kod endpointu o tym zapomniał.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import RulebookDep, SessionDep, SettingsDep
from app.core import audit
from app.iam.deps import require
from app.iam.redaction import PERSONAL_PERMISSION, RedactingRoute
from app.iam.tokens import Principal
from app.matching.engine import ACTIVE_STATUSES
from app.models import (
    Asset,
    AssetAssignment,
    AssetSource,
    CoverageSnapshot,
    Finding,
    Location,
    NetworkSegment,
    OrgUnit,
    Person,
)
from app.models.base import utcnow
from app.notifications.engine import notify
from app.org.coverage import as_view, measure
from app.org.privacy import DEMO_LABEL, person_view, record_personal_view
from app.org.shadow import NON_DEVICE_TYPES, SOURCE_LABELS, evaluate_shadow

router = APIRouter(prefix="/api/org", route_class=RedactingRoute, tags=["organizacja"])
LEVELS = ("krytyczny", "wysoki", "średni", "niski")
Pseudonyms = Annotated[bool, Query(description="Pokaż pseudonimy zamiast nazwisk")]


class Coverage(BaseModel):
    day: str
    assets_total: int
    unknown_devices: int
    open_findings: int
    critical_findings: int
    with_owner_pct: float
    scanned_recently_pct: float
    known_version_pct: float


class UnitOut(BaseModel):
    id: uuid.UUID
    name: str
    parent_id: uuid.UUID | None
    devices: int
    unknown: int
    open_findings: int
    critical: int
    worst_level: str | None


class PlaceOut(BaseModel):
    id: uuid.UUID
    name: str
    devices: int


class OverviewOut(BaseModel):
    demo: bool
    demo_label: str | None
    units: list[UnitOut]
    locations: list[PlaceOut]
    coverage: Coverage
    trend: list[Coverage]
    unassigned_devices: int


class PersonOut(BaseModel):
    id: uuid.UUID
    pseudonym: str
    display_name: str
    job_title: str | None
    active: bool
    left_at: str | None


class DeviceOut(BaseModel):
    id: uuid.UUID
    name: str
    type: str
    status: str
    exposure: str
    criticality: int
    unit: str | None
    unit_id: uuid.UUID | None
    location: str | None
    segment: str | None
    owners: list[PersonOut]
    users: list[PersonOut]
    sources: list[str]
    in_cmdb: bool
    confirmed: bool
    open_findings: int
    worst_level: str | None
    max_score: float
    first_seen: datetime
    last_seen: datetime
    last_scan: datetime | None


class DevicesOut(BaseModel):
    items: list[DeviceOut]
    total: int
    demo_label: str | None


class PeopleRow(PersonOut):
    unit: str | None
    devices: int


def _worst(levels: list[str]) -> str | None:
    for level in LEVELS:
        if level in levels:
            return level
    return None


def _show_names(principal: Principal, pseudonyms: bool) -> bool:
    return principal.can(PERSONAL_PERMISSION) and not pseudonyms


def _findings_by_asset(session: Session) -> dict[uuid.UUID, list[Finding]]:
    out: dict[uuid.UUID, list[Finding]] = defaultdict(list)
    for finding in session.scalars(select(Finding).where(Finding.status.in_(ACTIVE_STATUSES))):
        out[finding.asset_id].append(finding)
    return out


def _devices_query() -> Any:
    return select(Asset).where(
        Asset.type.not_in(NON_DEVICE_TYPES), Asset.status.in_(("active", "shadow", "missing"))
    )


@router.get(
    "/overview", response_model=OverviewOut, dependencies=[Depends(require("inventory:read"))]
)
def overview(session: SessionDep, settings: SettingsDep) -> OverviewOut:
    """Organizacja w liczbach: działy, lokalizacje, pokrycie dziś i trend z 30 dni."""
    devices = session.scalars(_devices_query()).all()
    findings = _findings_by_asset(session)
    units = session.scalars(select(OrgUnit).order_by(OrgUnit.name)).all()
    per_unit: dict[uuid.UUID | None, list[Asset]] = defaultdict(list)
    for asset in devices:
        per_unit[asset.org_unit_id].append(asset)
    unit_rows = []
    for unit in units:
        assets = per_unit.get(unit.id, [])
        unit_findings = [f for a in assets for f in findings.get(a.id, [])]
        unit_rows.append(
            UnitOut(
                id=unit.id,
                name=unit.name,
                parent_id=unit.parent_id,
                devices=len(assets),
                unknown=sum(1 for a in assets if a.status == "shadow"),
                open_findings=len(unit_findings),
                critical=sum(1 for f in unit_findings if f.risk_level == "krytyczny"),
                worst_level=_worst([f.risk_level for f in unit_findings]),
            )
        )
    per_location: dict[uuid.UUID, int] = defaultdict(int)
    for asset in devices:
        if asset.location_id:
            per_location[asset.location_id] += 1
    locations = [
        PlaceOut(id=loc.id, name=loc.name, devices=per_location.get(loc.id, 0))
        for loc in session.scalars(select(Location).order_by(Location.name))
    ]
    # Dzisiejsza wartość liczona na żywo; trend z dziennych pomiarów (beat).
    today = measure(session)
    current = Coverage(
        **as_view(CoverageSnapshot(day=utcnow().date(), **today))  # nie zapisujemy
    )
    since = utcnow().date() - timedelta(days=30)
    trend = [
        Coverage(**as_view(row))
        for row in session.scalars(
            select(CoverageSnapshot)
            .where(CoverageSnapshot.day >= since)
            .order_by(CoverageSnapshot.day)
        )
    ]
    return OverviewOut(
        demo=settings.demo_mode,
        demo_label=DEMO_LABEL if settings.demo_mode else None,
        units=unit_rows,
        locations=locations,
        coverage=current,
        trend=trend,
        unassigned_devices=len(per_unit.get(None, [])),
    )


def _people_by_asset(
    session: Session, asset_ids: set[uuid.UUID]
) -> tuple[dict[uuid.UUID, dict[str, list[Person]]], list[Person]]:
    out: dict[uuid.UUID, dict[str, list[Person]]] = defaultdict(lambda: defaultdict(list))
    seen: list[Person] = []
    if not asset_ids:
        return out, seen
    rows = session.execute(
        select(AssetAssignment, Person)
        .join(Person, AssetAssignment.person_id == Person.id)
        .where(AssetAssignment.asset_id.in_(asset_ids))
        .order_by(Person.pseudonym_no)
    ).all()
    for assignment, person in rows:
        out[assignment.asset_id][assignment.role].append(person)
        seen.append(person)
    return out, seen


def _device_rows(
    session: Session, assets: list[Asset], show_names: bool
) -> tuple[list[DeviceOut], list[Person]]:
    ids = {a.id for a in assets}
    findings = _findings_by_asset(session)
    people, seen = _people_by_asset(session, ids)
    units = {u.id: u.name for u in session.scalars(select(OrgUnit))}
    locations = {loc.id: loc.name for loc in session.scalars(select(Location))}
    segments = {s.id: s.name for s in session.scalars(select(NetworkSegment))}
    sources: dict[uuid.UUID, list[str]] = defaultdict(list)
    last_scan: dict[uuid.UUID, datetime] = {}
    for row in session.scalars(select(AssetSource).where(AssetSource.asset_id.in_(ids))):
        sources[row.asset_id].append(row.source)
        if row.source == "scan":
            last_scan[row.asset_id] = row.last_seen
    rows = []
    for asset in assets:
        own = findings.get(asset.id, [])
        assigned = people.get(asset.id, {})
        rows.append(
            DeviceOut(
                id=asset.id,
                name=asset.name,
                type=asset.type,
                status=asset.status,
                exposure=asset.exposure,
                criticality=asset.criticality,
                unit=units.get(asset.org_unit_id) if asset.org_unit_id else None,
                unit_id=asset.org_unit_id,
                location=locations.get(asset.location_id) if asset.location_id else None,
                segment=segments.get(asset.segment_id) if asset.segment_id else None,
                owners=[
                    PersonOut(**person_view(p, show_names=show_names))
                    for p in assigned.get("owner", [])
                ],
                users=[
                    PersonOut(**person_view(p, show_names=show_names))
                    for p in assigned.get("user", [])
                ],
                sources=sorted(SOURCE_LABELS.get(s, s) for s in sources.get(asset.id, [])),
                in_cmdb=asset.in_cmdb,
                confirmed=asset.confirmed,
                open_findings=len(own),
                worst_level=_worst([f.risk_level for f in own]),
                max_score=max((f.risk_score for f in own), default=0.0),
                first_seen=asset.first_seen,
                last_seen=asset.last_seen,
                last_scan=last_scan.get(asset.id),
            )
        )
    return rows, seen


@router.get("/devices", response_model=DevicesOut)
def list_devices(
    session: SessionDep,
    settings: SettingsDep,
    principal: Annotated[Principal, Depends(require("inventory:read"))],
    unit: uuid.UUID | None = None,
    location: uuid.UUID | None = None,
    unknown: bool | None = None,
    pseudonyms: Pseudonyms = False,
) -> DevicesOut:
    """Urządzenia z działem, właścicielem i stanem zagrożeń. `unknown=true`: shadow IT."""
    query = _devices_query()
    if unit is not None:
        children = [u.id for u in session.scalars(select(OrgUnit).where(OrgUnit.parent_id == unit))]
        query = query.where(Asset.org_unit_id.in_([unit, *children]))
    if location is not None:
        query = query.where(Asset.location_id == location)
    if unknown is True:
        query = query.where(Asset.status == "shadow")
    assets = list(session.scalars(query.order_by(Asset.name)).all())
    show = _show_names(principal, pseudonyms)
    rows, seen = _device_rows(session, assets, show)
    rows.sort(key=lambda r: (-r.max_score, r.name.lower()))
    if show:
        record_personal_view(session, actor=principal.actor, people=seen, endpoint="org/devices")
    return DevicesOut(
        items=rows, total=len(rows), demo_label=DEMO_LABEL if settings.demo_mode else None
    )


@router.get("/devices/{asset_id}", response_model=DeviceOut)
def get_device(
    asset_id: uuid.UUID,
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("inventory:read"))],
    pseudonyms: Pseudonyms = False,
) -> DeviceOut:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono urządzenia")
    show = _show_names(principal, pseudonyms)
    rows, seen = _device_rows(session, [asset], show)
    if show:
        record_personal_view(
            session, actor=principal.actor, people=seen, endpoint=f"org/devices/{asset_id}"
        )
    return rows[0]


@router.get("/people", response_model=list[PeopleRow])
def list_people(
    session: SessionDep,
    principal: Annotated[Principal, Depends(require("inventory:read"))],
    pseudonyms: Pseudonyms = False,
) -> list[PeopleRow]:
    """Ludzie i liczba ich urządzeń. Bez `personal_data:view`: same pseudonimy."""
    show = _show_names(principal, pseudonyms)
    units = {u.id: u.name for u in session.scalars(select(OrgUnit))}
    counts: dict[uuid.UUID, int] = defaultdict(int)
    for person_id in session.scalars(select(AssetAssignment.person_id)):
        counts[person_id] += 1
    people = list(session.scalars(select(Person).order_by(Person.pseudonym_no)).all())
    if show:
        record_personal_view(session, actor=principal.actor, people=people, endpoint="org/people")
    return [
        PeopleRow(
            **person_view(p, show_names=show),
            unit=units.get(p.org_unit_id) if p.org_unit_id else None,
            devices=counts.get(p.id, 0),
        )
        for p in people
    ]


@router.post("/devices/{asset_id}/confirm", response_model=DeviceOut)
def confirm_device(
    asset_id: uuid.UUID,
    session: SessionDep,
    rulebook: RulebookDep,
    principal: Annotated[Principal, Depends(require("inventory:write"))],
) -> DeviceOut:
    """Człowiek potwierdza nieznane urządzenie; reguła shadow IT od razu zamyka finding."""
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nie znaleziono urządzenia")
    asset.confirmed = True
    audit.record(
        session,
        audit.AuditEvent(
            actor=principal.actor,
            action="asset_confirmed",
            reason=f"Urządzenie {asset.name} potwierdzone przez człowieka",
            inputs={"status_before": asset.status},
            object_type="asset",
            object_id=str(asset.id),
        ),
    )
    session.flush()
    notify(session, evaluate_shadow(session, rulebook.scoring), rulebook.notifications)
    rows, _ = _device_rows(session, [asset], show_names=False)
    return rows[0]
