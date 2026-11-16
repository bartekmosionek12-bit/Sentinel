"""Inwentarz: import CSV, scalanie ze skanem, shadow IT i historia zmian."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.scope_guard import Intrusiveness, ScopeConfig, ScopedNetwork, ScopeGuard
from app.inventory.service import (
    UNKNOWN_PRODUCT,
    asset_fingerprint,
    import_assets,
    parse_assets_csv,
    record_discovery,
    record_host_scan,
)
from app.models import Asset, AssetHistory, AuditLog, Software
from app.scanners.models import DiscoveredHost, HostScan, ServiceInfo
from app.scanners.nmap import parse_nmap_xml
from tests.conftest import FakeResolver, MemoryAudit
from tests.scanner_fakes import fixture

CSV = """name,type,address,exposure,criticality,owner,tags
web-01,host,172.30.99.10,internet,5,Zespół WWW,prod;www
cache-01,host,172.30.99.14,internal,2,,
old-01,host,172.30.99.77,internal,3,,
"""


@pytest.fixture
def network(audit_sink: MemoryAudit) -> ScopedNetwork:
    guard = ScopeGuard(
        ScopeConfig.from_dict(
            {"allow": {"cidrs": ["172.30.99.0/24"]}, "deny": {"cidrs": ["172.30.99.1/32"]}}
        ),
        audit=audit_sink,
        resolver=FakeResolver(),
    )
    return guard.authorize_network(
        "172.30.99.0/24", tool="nmap", intrusiveness=Intrusiveness.LIGHT, rule_name="test"
    )


def _import(session: Session, text: str = CSV) -> None:
    rows, errors = parse_assets_csv(text)
    assert errors == []
    import_assets(session, rows, source="csv", actor="test")


def _asset(session: Session, ip: str) -> Asset:
    asset = session.scalar(select(Asset).where(Asset.fingerprint == f"host:{ip}"))
    assert asset is not None
    return asset


def _changes(session: Session, asset: Asset) -> list[str]:
    return list(
        session.scalars(
            select(AssetHistory.change)
            .where(AssetHistory.asset_id == asset.id)
            .order_by(AssetHistory.created_at)
        )
    )


def test_fingerprint_merges_hosts_by_address_and_others_by_name() -> None:
    assert asset_fingerprint("host", "Web-01", "172.30.99.10") == "host:172.30.99.10"
    assert asset_fingerprint("host", "Web-01.") == "host:web-01"
    assert asset_fingerprint("domain", "Example.LAB.") == "domain:example.lab"


def test_csv_rows_with_errors_are_reported_and_skipped() -> None:
    rows, errors = parse_assets_csv(
        "name,type,address,exposure,criticality\n"
        "ok,host,10.0.0.1,internal,3\n"
        ",host,10.0.0.2,internal,3\n"
        "bad-type,router,,internal,3\n"
        "bad-exposure,host,,public,3\n"
        "bad-crit,host,,internal,9\n"
        "bad-crit2,host,,internal,wysoka\n"
        "bad-ip,host,10.0.0.999,internal,3\n"
    )
    assert [r["name"] for r in rows] == ["ok"]
    assert [e.split(":")[0] for e in errors] == [f"Wiersz {n}" for n in range(3, 9)]
    assert parse_assets_csv("foo,bar\n1,2\n") == ([], ["Brak nagłówka z kolumną `name`"])


def test_import_creates_then_updates_and_writes_history_and_audit(session: Session) -> None:
    _import(session)
    web = _asset(session, "172.30.99.10")
    assert (web.name, web.exposure, web.criticality, web.tags) == (
        "web-01",
        "internet",
        5,
        ["prod", "www"],
    )
    assert web.status == "active"

    rows, _ = parse_assets_csv(CSV.replace("internet,5", "internal,4"))
    result = import_assets(session, rows, source="csv", actor="test")
    assert (result.created, result.updated, result.unchanged) == (0, 1, 2)
    assert (web.exposure, web.criticality) == ("internal", 4)
    assert _changes(session, web) == ["imported", "updated"]
    assert session.scalars(select(AuditLog.action)).all() == ["assets_imported"] * 2


def test_discovery_marks_shadow_missing_and_reappeared(
    session: Session, network: ScopedNetwork
) -> None:
    _import(session)
    hosts = [DiscoveredHost(h.ip) for h in parse_nmap_xml(fixture("nmap_discovery.xml"))]
    result = record_discovery(session, network, hosts)

    assert [a.name for a in result.new] == ["172.30.99.11"]
    shadow = _asset(session, "172.30.99.11")
    assert shadow.status == "shadow"
    assert _changes(session, shadow) == ["discovered"]
    assert [a.name for a in result.missing] == ["old-01"]
    assert _asset(session, "172.30.99.77").status == "missing"
    assert len(result.seen) == 3

    again = record_discovery(session, network, [*hosts, DiscoveredHost("172.30.99.77")])
    assert again.new == []
    assert again.missing == []
    assert [a.name for a in again.reappeared] == ["old-01"]
    assert _asset(session, "172.30.99.77").status == "active"


def test_discovery_never_touches_assets_outside_network_or_on_denylist(
    session: Session, network: ScopedNetwork
) -> None:
    _import(
        session,
        "name,type,address,exposure,criticality\n"
        "gateway,host,172.30.99.1,internal,3\n"
        "elsewhere,host,10.0.0.5,internal,3\n",
    )
    result = record_discovery(session, network, [])
    assert result.missing == []
    assert _asset(session, "172.30.99.1").status == "active"
    assert _asset(session, "10.0.0.5").status == "active"


def test_importing_a_shadow_host_adopts_it(session: Session, network: ScopedNetwork) -> None:
    record_discovery(session, network, [DiscoveredHost("172.30.99.10")])
    assert _asset(session, "172.30.99.10").status == "shadow"
    _import(session)
    web = _asset(session, "172.30.99.10")
    assert (web.status, web.name, web.criticality) == ("active", "web-01", 5)


def test_host_scan_stores_services_and_diffs_the_next_scan(session: Session) -> None:
    _import(session)
    web = _asset(session, "172.30.99.10")
    (scan,) = parse_nmap_xml(fixture("nmap_services_httpd.xml"))
    diff = record_host_scan(session, web, scan)
    assert len(diff.added) == 3
    software = {
        s.port: s for s in session.scalars(select(Software).where(Software.asset_id == web.id))
    }
    assert (software[80].product, software[80].version) == ("Apache httpd", "2.4.49")
    assert software[80].cpe == "cpe:/a:apache:http_server:2.4.49"
    assert software[80].raw_banner == "Apache httpd 2.4.49 (Unix)"
    assert (software[3000].product, software[3000].raw_banner) == (UNKNOWN_PRODUCT, "ppp")
    assert web.attributes["open_ports"] == [80, 3000, 6379]
    assert _changes(session, web) == ["imported", "scanned"]

    assert not record_host_scan(session, web, scan).changed
    assert _changes(session, web) == ["imported", "scanned"]

    upgraded = HostScan(
        ip="172.30.99.10",
        services=(ServiceInfo(port=80, protocol="tcp", product="Apache httpd", version="2.4.62"),),
    )
    diff = record_host_scan(session, web, upgraded)
    assert [(s.product, s.version) for s in diff.added] == [("Apache httpd", "2.4.62")]
    removed: list[dict[str, Any]] = diff.removed
    assert sorted(r["port"] for r in removed) == [80, 3000, 6379]
    assert web.attributes["open_ports"] == [80]
    assert _changes(session, web)[-1] == "services_changed"
