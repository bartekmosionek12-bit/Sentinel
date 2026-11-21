"""Synchronizacja organizacji z AD/MDM/CMDB/DHCP do inwentarza (#18, ARCHITECTURE §7.1).

Urządzenie z kilku źródeł to jeden zasób: scalamy po MAC, numerze seryjnym, adresie IP i
nazwie hosta, w tej kolejności. CMDB jest źródłem prawdy o dziale, lokalizacji, właścicielu i
krytyczności; inne źródła uzupełniają tylko puste pola. Osoby dostają stały numer pseudonimu
przy pierwszym pojawieniu się; osoba, której nie ma już w katalogu, jest oznaczona jako
nieaktywna (jej urządzenia zostają do wyjaśnienia), a nie kasowana.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import audit
from app.inventory.service import asset_fingerprint
from app.inventory.sources import touch_source
from app.models import (
    Asset,
    AssetAssignment,
    AssetHistory,
    Location,
    NetworkSegment,
    OrgUnit,
    Person,
)
from app.models.base import utcnow
from app.models.inventory import ASSET_TYPES
from app.org.sources import DeviceRecord, OrgSnapshot

FIRST_PSEUDONYM = 101
AUTHORITATIVE = "cmdb"


@dataclass
class SyncResult:
    org_units: int = 0
    locations: int = 0
    segments: int = 0
    people_created: int = 0
    people_left: int = 0
    devices_created: int = 0
    devices_merged: int = 0
    assignments_created: int = 0
    owners_migrated: int = 0
    sources: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return dict(self.__dict__)


class _Index:
    """Istniejące zasoby po kluczach scalania."""

    def __init__(self, session: Session) -> None:
        self.by: dict[str, dict[str, Asset]] = {"mac": {}, "serial": {}, "address": {}, "name": {}}
        for asset in session.scalars(select(Asset)).all():
            self.add(asset)

    def add(self, asset: Asset) -> None:
        attrs = asset.attributes or {}
        for key in ("mac", "serial", "address"):
            if attrs.get(key):
                self.by[key].setdefault(str(attrs[key]).lower(), asset)
        if asset.type not in ("domain", "ip", "service", "application"):
            self.by["name"].setdefault(asset.name.lower(), asset)

    def find(self, record: DeviceRecord) -> Asset | None:
        for key, value in (
            ("mac", record.mac),
            ("serial", record.serial),
            ("address", record.address),
            ("name", record.hostname),
        ):
            if value and (found := self.by[key].get(value.lower())):
                return found
        return None


def _upsert_org(session: Session, snapshot: OrgSnapshot, result: SyncResult) -> dict[str, Any]:
    units = {u.external_id: u for u in session.scalars(select(OrgUnit)).all()}
    for record in snapshot.org_units:
        unit = units.get(record.external_id)
        if unit is None:
            unit = OrgUnit(external_id=record.external_id, name=record.name)
            session.add(unit)
            units[record.external_id] = unit
            result.org_units += 1
        unit.name = record.name
    session.flush()
    for record in snapshot.org_units:
        parent = units.get(record.parent) if record.parent else None
        units[record.external_id].parent_id = parent.id if parent else None

    locations = {loc.external_id: loc for loc in session.scalars(select(Location)).all()}
    for loc_record in snapshot.locations:
        location = locations.get(loc_record.external_id)
        if location is None:
            location = Location(external_id=loc_record.external_id, name=loc_record.name)
            session.add(location)
            locations[loc_record.external_id] = location
            result.locations += 1
        location.name, location.address = loc_record.name, loc_record.address
    session.flush()

    segments = {s.cidr: s for s in session.scalars(select(NetworkSegment)).all()}
    for seg_record in snapshot.segments:
        cidr = str(ip_network(seg_record.cidr, strict=False))
        segment = segments.get(cidr)
        if segment is None:
            segment = NetworkSegment(cidr=cidr, name=seg_record.name)
            session.add(segment)
            segments[cidr] = segment
            result.segments += 1
        segment.name = seg_record.name
        location = locations.get(seg_record.location) if seg_record.location else None
        segment.location_id = location.id if location else None
    session.flush()
    return {"units": units, "locations": locations, "segments": list(segments.values())}


def _upsert_people(
    session: Session, snapshot: OrgSnapshot, units: dict[str, OrgUnit], now: datetime
) -> tuple[dict[str, Person], int, int]:
    people = {p.external_id: p for p in session.scalars(select(Person)).all()}
    next_no = max(FIRST_PSEUDONYM - 1, session.scalar(select(func.max(Person.pseudonym_no))) or 0)
    created = left = 0
    seen: set[str] = set()
    for record in snapshot.people:
        seen.add(record.external_id)
        person = people.get(record.external_id)
        if person is None:
            next_no += 1
            person = Person(
                source=record.source,
                external_id=record.external_id,
                full_name=record.full_name,
                pseudonym_no=next_no,
                active=True,
            )
            session.add(person)
            people[record.external_id] = person
            created += 1
        unit = units.get(record.org_unit) if record.org_unit else None
        # Osoby, które już odeszły, nie dostają z powrotem nazwiska (retencja §15 je usuwa).
        if record.active or person.active:
            person.full_name, person.job_title = record.full_name, record.job_title
        person.org_unit_id = unit.id if unit else None
        if record.active:
            person.active, person.left_at = True, None
        elif person.active:
            person.active, person.left_at = False, now
            left += 1
    synced_sources = {p.source for p in snapshot.people}
    for external_id, person in people.items():
        if person.source in synced_sources and external_id not in seen and person.active:
            person.active, person.left_at = False, now
            left += 1
    session.flush()
    return people, created, left


def _segment_for(address: str | None, segments: list[NetworkSegment]) -> NetworkSegment | None:
    if not address:
        return None
    try:
        ip = ip_address(address)
    except ValueError:
        return None
    for segment in segments:
        network = ip_network(segment.cidr, strict=False)
        if ip.version == network.version and ip in network:
            return segment
    return None


def _assign(session: Session, asset: Asset, person: Person, role: str) -> bool:
    exists = session.scalar(
        select(AssetAssignment.id).where(
            AssetAssignment.asset_id == asset.id,
            AssetAssignment.person_id == person.id,
            AssetAssignment.role == role,
        )
    )
    if exists:
        return False
    session.add(AssetAssignment(asset_id=asset.id, person_id=person.id, role=role))
    return True


def sync_organization(
    session: Session, snapshot: OrgSnapshot, *, actor: str, now: datetime | None = None
) -> SyncResult:
    """Wczytuje migawkę ze źródeł do bazy. Nie skanuje sieci i nic nie zapisuje w źródłach."""
    now = now or utcnow()
    result = SyncResult(sources=list(snapshot.sources))
    org = _upsert_org(session, snapshot, result)
    units, locations, segments = org["units"], org["locations"], org["segments"]
    people, result.people_created, result.people_left = _upsert_people(
        session, snapshot, units, now
    )

    index = _Index(session)
    # CMDB najpierw: tworzy zasób z właściwym typem, a jego dział, lokalizacja i właściciel
    # wygrywają; pozostałe źródła tylko uzupełniają puste pola.
    ordered = sorted(snapshot.devices, key=lambda d: d.source != AUTHORITATIVE)
    for record in ordered:
        asset = index.find(record)
        name = record.hostname or record.address or record.serial or "urządzenie bez nazwy"
        if asset is None:
            kind = record.type if record.type in ASSET_TYPES else "host"
            fingerprint = asset_fingerprint(kind, name, record.address)
            asset = Asset(
                type=kind,
                name=name,
                fingerprint=fingerprint,
                status="active",
                attributes={},
                first_seen=now,
                last_seen=now,
            )
            session.add(asset)
            session.flush()
            session.add(
                AssetHistory(
                    asset_id=asset.id,
                    change="discovered",
                    diff={"source": record.source, "name": name, "address": record.address},
                )
            )
            result.devices_created += 1
        else:
            result.devices_merged += 1
        attrs = dict(asset.attributes or {})
        for key in ("address", "mac", "serial", "os"):
            value = getattr(record, key)
            if value and not attrs.get(key):
                attrs[key] = value
        asset.attributes = attrs
        authoritative = record.source == AUTHORITATIVE
        unit = units.get(record.org_unit) if record.org_unit else None
        if unit and (authoritative or asset.org_unit_id is None):
            asset.org_unit_id = unit.id
        location = locations.get(record.location) if record.location else None
        if location and (authoritative or asset.location_id is None):
            asset.location_id = location.id
        segment = _segment_for(attrs.get("address"), segments)
        if segment is not None:
            asset.segment_id = segment.id
            if asset.location_id is None:
                asset.location_id = segment.location_id
        if authoritative and record.criticality:
            asset.criticality = record.criticality
        for role, ref in (("owner", record.owner), ("user", record.user)):
            person = people.get(ref) if ref else None
            if person is None:
                continue
            if _assign(session, asset, person, role):
                result.assignments_created += 1
            # Urządzenie bez działu (np. tablet z MDM) należy do działu swojego użytkownika.
            if asset.org_unit_id is None and person.org_unit_id is not None:
                asset.org_unit_id = person.org_unit_id
        touch_source(session, asset, record.source, record.external_id, now=now)
        session.flush()
        index.add(asset)

    # Stary tekst `owner` z CSV („Zespół WWW”) wskazuje dział o tej samej nazwie.
    by_name = {u.name.lower(): u for u in units.values()}
    for asset in session.scalars(
        select(Asset).where(Asset.org_unit_id.is_(None), Asset.owner.is_not(None))
    ).all():
        unit = by_name.get((asset.owner or "").strip().lower())
        if unit is not None:
            asset.org_unit_id = unit.id
            result.owners_migrated += 1
    session.flush()

    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="org_synced",
            reason="Synchronizacja organizacji ze źródeł: " + ", ".join(snapshot.sources),
            # Bez nazwisk: w audycie tylko liczby.
            inputs=result.summary(),
            object_type="inventory",
        ),
    )
    return result
