"""Inwentarz: import zasobów oraz zapis wyników odkrywania i skanów usług.

Ten sam zasób z importu i ze skanu scala się po odcisku (`fingerprint`). Każda zmiana
stanu zostawia wiersz `AssetHistory`, więc da się odtworzyć, co i kiedy się zmieniło.
"""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.scope_guard import ScopedNetwork
from app.matching.cpe import parse_cpe
from app.models import Asset, AssetHistory, Software
from app.models.base import utcnow
from app.models.inventory import ASSET_EXPOSURES, ASSET_TYPES
from app.scanners.models import DiscoveredHost, HostScan, ServiceInfo

UNKNOWN_PRODUCT = "unknown"
SCAN_SOURCE = "nmap"
CSV_COLUMNS = ("name", "type", "address", "exposure", "criticality", "owner", "tags")


def asset_fingerprint(asset_type: str, name: str, address: str | None = None) -> str:
    """Host z adresem IP scalamy po adresie, resztę po typie i nazwie."""
    if asset_type == "host" and address:
        return f"host:{address}"
    return f"{asset_type}:{name.strip().lower().rstrip('.')}"


def _history(
    session: Session,
    asset: Asset,
    change: str,
    diff: dict[str, Any],
    scan_run_id: uuid.UUID | None = None,
) -> None:
    session.add(AssetHistory(asset_id=asset.id, scan_run_id=scan_run_id, change=change, diff=diff))


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    errors: list[str] = field(default_factory=list)


def parse_assets_csv(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Zwraca poprawne wiersze i listę błędów z numerami wierszy. Nie zgaduje wartości."""
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    if reader.fieldnames is None or "name" not in reader.fieldnames:
        return [], ["Brak nagłówka z kolumną `name`"]
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for number, raw in enumerate(reader, start=2):
        values = {k: (v or "").strip() for k, v in raw.items() if k}
        name = values.get("name", "")
        asset_type = values.get("type") or "host"
        exposure = values.get("exposure") or "internal"
        address = values.get("address") or None
        if not name:
            errors.append(f"Wiersz {number}: pusta nazwa")
            continue
        if asset_type not in ASSET_TYPES:
            errors.append(f"Wiersz {number}: nieznany typ {asset_type!r}")
            continue
        if exposure not in ASSET_EXPOSURES:
            errors.append(f"Wiersz {number}: nieznana ekspozycja {exposure!r}")
            continue
        try:
            criticality = int(values.get("criticality") or 3)
        except ValueError:
            criticality = 0
        if not 1 <= criticality <= 5:
            errors.append(f"Wiersz {number}: krytyczność musi być liczbą od 1 do 5")
            continue
        if address:
            try:
                address = str(ip_address(address))
            except ValueError:
                errors.append(f"Wiersz {number}: {address!r} nie jest adresem IP")
                continue
        rows.append(
            {
                "name": name,
                "type": asset_type,
                "address": address,
                "exposure": exposure,
                "criticality": criticality,
                "owner": values.get("owner") or None,
                "tags": [t.strip() for t in values.get("tags", "").split(";") if t.strip()],
            }
        )
    return rows, errors


def import_assets(
    session: Session, rows: Iterable[dict[str, Any]], *, source: str, actor: str
) -> ImportResult:
    result = ImportResult()
    for row in rows:
        fingerprint = asset_fingerprint(row["type"], row["name"], row.get("address"))
        declared = {
            "name": row["name"],
            "exposure": row["exposure"],
            "criticality": row["criticality"],
            "owner": row.get("owner"),
            "tags": list(row.get("tags") or []),
        }
        asset = session.scalar(select(Asset).where(Asset.fingerprint == fingerprint))
        if asset is None:
            attributes = {"address": row["address"]} if row.get("address") else {}
            asset = Asset(
                type=row["type"], fingerprint=fingerprint, attributes=attributes, **declared
            )
            session.add(asset)
            session.flush()
            _history(session, asset, "imported", {"source": source, **declared})
            result.created += 1
            continue
        diff = {
            key: {"before": getattr(asset, key), "after": value}
            for key, value in declared.items()
            if getattr(asset, key) != value
        }
        if asset.status == "shadow":
            # Zasób znaleziony wcześniej przez skan właśnie trafił do inwentarza.
            diff["status"] = {"before": "shadow", "after": "active"}
            asset.status = "active"
        if not diff:
            result.unchanged += 1
            continue
        for key, value in declared.items():
            setattr(asset, key, value)
        _history(session, asset, "updated", {"source": source, **diff})
        result.updated += 1
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="assets_imported",
            reason=f"Import zasobów ze źródła {source}",
            inputs={
                "source": source,
                "created": result.created,
                "updated": result.updated,
                "unchanged": result.unchanged,
                "errors": result.errors[:20],
            },
            object_type="inventory",
        ),
    )
    return result


@dataclass
class DiscoveryResult:
    """Co zmieniło odkrywanie hostów w jednej sieci."""

    seen: list[Asset] = field(default_factory=list)
    new: list[Asset] = field(default_factory=list)
    reappeared: list[Asset] = field(default_factory=list)
    missing: list[Asset] = field(default_factory=list)


def _inside(raw: object, network: ScopedNetwork) -> bool:
    """Czy adres leży w autoryzowanej sieci i nie jest z niej wykluczony."""
    try:
        address = ip_address(str(raw))
    except ValueError:
        return False
    if address.version != network.network.version or address not in network.network:
        return False
    return not any(
        address.version == excluded.version and address in excluded for excluded in network.excluded
    )


def _host_assets_in(session: Session, network: ScopedNetwork) -> dict[str, Asset]:
    found: dict[str, Asset] = {}
    for asset in session.scalars(select(Asset).where(Asset.type == "host")):
        raw = (asset.attributes or {}).get("address")
        if raw and _inside(raw, network):
            found[str(ip_address(raw))] = asset
    return found


def record_discovery(
    session: Session,
    network: ScopedNetwork,
    hosts: Sequence[DiscoveredHost],
    scan_run_id: uuid.UUID | None = None,
) -> DiscoveryResult:
    """Scala wynik odkrywania z inwentarzem: nowe (shadow IT), widziane, znikające."""
    now = utcnow()
    known = _host_assets_in(session, network)
    result = DiscoveryResult()
    # Narzędzie mogło zwrócić adres spoza sieci albo z denylisty: taki wynik pomijamy.
    up = {host.ip: host for host in hosts if _inside(host.ip, network)}
    for ip, host in sorted(up.items()):
        asset = known.get(ip)
        if asset is None:
            asset = Asset(
                type="host",
                name=host.hostname or ip,
                fingerprint=asset_fingerprint("host", ip, ip),
                status="shadow",
                attributes={"address": ip, "discovered_by": SCAN_SOURCE},
                first_seen=now,
                last_seen=now,
            )
            session.add(asset)
            session.flush()
            _history(
                session,
                asset,
                "discovered",
                {"address": ip, "note": "Host odpowiada, a nie ma go w inwentarzu (shadow IT)"},
                scan_run_id,
            )
            result.new.append(asset)
        else:
            asset.last_seen = now
            if asset.status == "missing":
                asset.status = "active"
                _history(
                    session,
                    asset,
                    "reappeared",
                    {"status": {"before": "missing", "after": "active"}},
                    scan_run_id,
                )
                result.reappeared.append(asset)
        result.seen.append(asset)
    for ip, asset in sorted(known.items()):
        if ip in up or asset.status not in ("active", "shadow"):
            continue
        before = asset.status
        asset.status = "missing"
        _history(
            session,
            asset,
            "missing",
            {"status": {"before": before, "after": "missing"}},
            scan_run_id,
        )
        result.missing.append(asset)
    session.flush()
    return result


@dataclass
class ServiceDiff:
    added: list[Software] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


def _tool_cpe(service: ServiceInfo) -> str | None:
    for cpe in service.cpes:
        parsed = parse_cpe(cpe)
        if parsed and (cpe.startswith("cpe:/a") or cpe.startswith("cpe:2.3:a")):
            return cpe
    return None


def _describe(software: Software) -> dict[str, Any]:
    return {
        "product": software.product,
        "version": software.version,
        "port": software.port,
        "protocol": software.protocol,
    }


def record_host_scan(
    session: Session,
    asset: Asset,
    scan: HostScan,
    scan_run_id: uuid.UUID | None = None,
    *,
    full: bool = False,
) -> ServiceDiff:
    """Zapisuje usługi wykryte na hoście i zwraca różnicę względem poprzedniego skanu.

    `full=True` oznacza skan wszystkich portów. Porty znalezione tylko przez pełny skan
    są zapamiętywane, żeby późniejszy skan częściowy nie uznał ich za zamknięte.
    """
    now = utcnow()
    attributes = dict(asset.attributes or {})
    scanned_ports = {s.port for s in scan.services}
    beyond = set(attributes.get("full_scan_only_ports", []))
    if full:
        visible_to_partial = set(attributes.get("open_ports", [])) - beyond
        beyond = scanned_ports - visible_to_partial if "open_ports" in attributes else set()
    existing = {
        (s.product, s.version, s.port): s
        for s in session.scalars(
            select(Software).where(Software.asset_id == asset.id, Software.source == SCAN_SOURCE)
        )
    }
    diff = ServiceDiff()
    seen: set[tuple[str, str, int | None]] = set()
    for service in scan.services:
        key: tuple[str, str, int | None] = (
            service.product or UNKNOWN_PRODUCT,
            service.version,
            service.port,
        )
        seen.add(key)
        software = existing.get(key)
        if software is not None:
            software.last_seen = now
            continue
        software = Software(
            asset_id=asset.id,
            product=key[0],
            version=service.version,
            raw_banner=service.banner or service.name or None,
            cpe=_tool_cpe(service),
            source=SCAN_SOURCE,
            port=service.port,
            protocol=service.protocol,
            first_seen=now,
            last_seen=now,
        )
        session.add(software)
        diff.added.append(software)
    for old_key, software in existing.items():
        if old_key in seen or (not full and software.port in beyond):
            continue
        diff.removed.append(_describe(software))
        session.delete(software)
    first_scan = "open_ports" not in attributes
    asset.attributes = {
        **attributes,
        "open_ports": sorted(scanned_ports if full else scanned_ports | beyond),
        "full_scan_only_ports": sorted(beyond),
        "last_service_scan": now.isoformat(),
    }
    asset.last_seen = now
    session.flush()
    if diff.changed or first_scan:
        _history(
            session,
            asset,
            "scanned" if first_scan else "services_changed",
            {"added": [_describe(s) for s in diff.added], "removed": diff.removed},
            scan_run_id,
        )
        session.flush()
    return diff


PACKAGE_SOURCE = "ssh"


def host_asset(session: Session, address: str, hostname: str | None = None) -> Asset:
    """Zasób hosta o danym adresie. Nieznany host trafia do inwentarza jako shadow IT."""
    fingerprint = asset_fingerprint("host", address, address)
    asset = session.scalar(select(Asset).where(Asset.fingerprint == fingerprint))
    if asset is not None:
        return asset
    now = utcnow()
    asset = Asset(
        type="host",
        name=hostname or address,
        fingerprint=fingerprint,
        status="shadow",
        attributes={"address": address, "discovered_by": "agent"},
        first_seen=now,
        last_seen=now,
    )
    session.add(asset)
    session.flush()
    _history(session, asset, "discovered", {"address": address, "note": "Host z zadania agenta"})
    return asset


def record_packages(
    session: Session, asset: Asset, manager: str, packages: Sequence[tuple[str, str]]
) -> ServiceDiff:
    """Zapisuje pakiety odczytane skanem uwierzytelnionym (źródło `ssh`) i zwraca różnicę."""
    now = utcnow()
    existing = {
        (s.product, s.version): s
        for s in session.scalars(
            select(Software).where(Software.asset_id == asset.id, Software.source == PACKAGE_SOURCE)
        )
    }
    diff = ServiceDiff()
    seen: set[tuple[str, str]] = set()
    for name, version in packages:
        key = (name[:255], version[:128])
        if key in seen:
            continue
        seen.add(key)
        software = existing.get(key)
        if software is not None:
            software.last_seen = now
            continue
        software = Software(
            asset_id=asset.id,
            product=key[0],
            version=key[1],
            raw_banner=f"{manager}: {key[0]} {key[1]}",
            source=PACKAGE_SOURCE,
            first_seen=now,
            last_seen=now,
        )
        session.add(software)
        diff.added.append(software)
    for key, software in existing.items():
        if key not in seen:
            diff.removed.append(_describe(software))
            session.delete(software)
    attributes = dict(asset.attributes or {})
    first = "package_manager" not in attributes
    asset.attributes = {
        **attributes,
        "package_manager": manager,
        "last_authenticated_scan": now.isoformat(),
    }
    asset.last_seen = now
    session.flush()
    if diff.changed or first:
        _history(
            session,
            asset,
            "packages_scanned" if first else "packages_changed",
            {
                "manager": manager,
                "added": len(diff.added),
                "removed": [f"{r['product']} {r['version']}" for r in diff.removed][:50],
            },
        )
        session.flush()
    return diff
