"""Źródła danych o organizacji: AD/Entra, MDM, CMDB, DHCP (#18, ARCHITECTURE §7.1).

W demo każde źródło to atrapa czytająca fikcyjne pliki JSON z `demo-lab/org/`. Prawdziwe
konektory (LDAP do AD, Microsoft Graph do Entra i Intune, API CMDB, eksport leasów DHCP)
mają zwracać ten sam `OrgSnapshot`, więc synchronizacja i reguły nie zmieniają się.
Konektory tylko CZYTAJĄ: nie zapisują nic w systemach organizacji.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class OrgUnitRecord:
    external_id: str
    name: str
    parent: str | None = None


@dataclass(frozen=True)
class LocationRecord:
    external_id: str
    name: str
    address: str | None = None


@dataclass(frozen=True)
class SegmentRecord:
    cidr: str
    name: str
    location: str | None = None


@dataclass(frozen=True)
class PersonRecord:
    source: str
    external_id: str
    full_name: str
    job_title: str | None
    org_unit: str | None
    active: bool = True


@dataclass(frozen=True)
class DeviceRecord:
    """Urządzenie z jednego źródła. Scalamy po MAC, numerze seryjnym, adresie albo nazwie."""

    source: str
    external_id: str | None
    hostname: str | None
    type: str = "host"
    address: str | None = None
    mac: str | None = None
    serial: str | None = None
    os: str | None = None
    org_unit: str | None = None
    location: str | None = None
    owner: str | None = None  # external_id osoby odpowiedzialnej (CMDB)
    user: str | None = None  # external_id użytkownika (MDM)
    criticality: int | None = None


@dataclass
class OrgSnapshot:
    org_units: list[OrgUnitRecord] = field(default_factory=list)
    locations: list[LocationRecord] = field(default_factory=list)
    segments: list[SegmentRecord] = field(default_factory=list)
    people: list[PersonRecord] = field(default_factory=list)
    devices: list[DeviceRecord] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def merge(self, other: OrgSnapshot) -> OrgSnapshot:
        return OrgSnapshot(
            self.org_units + other.org_units,
            self.locations + other.locations,
            self.segments + other.segments,
            self.people + other.people,
            self.devices + other.devices,
            self.sources + other.sources,
        )


class OrgSource(Protocol):
    @property
    def name(self) -> str: ...

    def fetch(self) -> OrgSnapshot: ...


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: oczekiwano obiektu JSON")
    return data


@dataclass(frozen=True)
class MockDirectory:
    """Atrapa AD (albo Entra ID): działy, osoby i konta komputerów."""

    path: Path
    name: str = "ad"

    def fetch(self) -> OrgSnapshot:
        data = _load(self.path)
        return OrgSnapshot(
            org_units=[
                OrgUnitRecord(u["id"], u["name"], u.get("parent")) for u in data["org_units"]
            ],
            people=[
                PersonRecord(
                    self.name,
                    p["id"],
                    p["full_name"],
                    p.get("job_title"),
                    p.get("org_unit"),
                    bool(p.get("active", True)),
                )
                for p in data["people"]
            ],
            devices=[
                DeviceRecord(
                    self.name,
                    c["id"],
                    c.get("hostname"),
                    c.get("type", "workstation"),
                    address=c.get("address"),
                    org_unit=c.get("org_unit"),
                    user=c.get("user"),
                )
                for c in data.get("computers", [])
            ],
            sources=[self.name],
        )


@dataclass(frozen=True)
class MockMdm:
    """Atrapa MDM (np. Intune): laptopy i urządzenia mobilne z przypisanym użytkownikiem."""

    path: Path
    name: str = "mdm"

    def fetch(self) -> OrgSnapshot:
        return OrgSnapshot(
            devices=[
                DeviceRecord(
                    self.name,
                    d["id"],
                    d.get("hostname"),
                    d.get("type", "laptop"),
                    address=d.get("address"),
                    mac=d.get("mac"),
                    serial=d.get("serial"),
                    os=d.get("os"),
                    user=d.get("user"),
                )
                for d in _load(self.path)["devices"]
            ],
            sources=[self.name],
        )


@dataclass(frozen=True)
class MockCmdb:
    """Atrapa CMDB: serwery i sprzęt sieciowy z działem, właścicielem i lokalizacją."""

    path: Path
    name: str = "cmdb"

    def fetch(self) -> OrgSnapshot:
        data = _load(self.path)
        return OrgSnapshot(
            locations=[
                LocationRecord(loc["id"], loc["name"], loc.get("address"))
                for loc in data.get("locations", [])
            ],
            segments=[
                SegmentRecord(s["cidr"], s["name"], s.get("location"))
                for s in data.get("segments", [])
            ],
            devices=[
                DeviceRecord(
                    self.name,
                    i["id"],
                    i.get("hostname"),
                    i.get("type", "server"),
                    address=i.get("address"),
                    org_unit=i.get("org_unit"),
                    location=i.get("location"),
                    owner=i.get("owner"),
                    criticality=i.get("criticality"),
                )
                for i in data["items"]
            ],
            sources=[self.name],
        )


@dataclass(frozen=True)
class MockDhcp:
    """Atrapa eksportu leasów DHCP: widzi każde urządzenie w sieci, także nieznane."""

    path: Path
    name: str = "dhcp"

    def fetch(self) -> OrgSnapshot:
        return OrgSnapshot(
            devices=[
                DeviceRecord(
                    self.name,
                    lease.get("mac"),
                    lease.get("hostname"),
                    address=lease["address"],
                    mac=lease.get("mac"),
                )
                for lease in _load(self.path)["leases"]
            ],
            sources=[self.name],
        )


def demo_sources(directory: Path) -> list[OrgSource]:
    """Atrapy w kolejności: katalog (działy i osoby) najpierw, potem urządzenia."""
    return [
        MockDirectory(directory / "ad.json"),
        MockCmdb(directory / "cmdb.json"),
        MockMdm(directory / "mdm.json"),
        MockDhcp(directory / "dhcp.json"),
    ]


def collect(sources: list[OrgSource]) -> OrgSnapshot:
    snapshot = OrgSnapshot()
    for source in sources:
        snapshot = snapshot.merge(source.fetch())
    return snapshot
