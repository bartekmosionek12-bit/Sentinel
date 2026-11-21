"""API organizacji: RBAC, pseudonimy, audyt podglądu danych osobowych, shadow IT (#18)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.inventory.service import import_assets, parse_assets_csv
from app.models import AuditLog, Finding
from app.org.coverage import record_snapshot
from app.org.shadow import evaluate_shadow
from app.org.sources import collect, demo_sources
from app.org.sync import sync_organization
from app.pipeline import Rulebook
from tests.conftest import TokenFactory
from tests.pipeline_helpers import RULES

ROOT = Path(__file__).resolve().parents[2]
RULEBOOK = Rulebook.from_dir(RULES)


@pytest.fixture
def org(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        rows, _ = parse_assets_csv((ROOT / "demo-lab" / "assets.csv").read_text("utf-8"))
        import_assets(session, rows, source="assets.csv", actor="test")
        sync_organization(session, collect(demo_sources(ROOT / "demo-lab" / "org")), actor="t")
        evaluate_shadow(session, RULEBOOK.scoring)
        record_snapshot(session)
        session.commit()


def _as(tokens: TokenFactory, role: str) -> dict[str, str]:
    return tokens.headers([role], username=f"{role}-1")


def _audits(factory: sessionmaker[Session], action: str) -> list[AuditLog]:
    with factory() as session:
        return list(session.scalars(select(AuditLog).where(AuditLog.action == action)).all())


@pytest.mark.usefixtures("org")
def test_overview_has_units_coverage_and_trend(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    body = anon_client.get("/api/org/overview", headers=_as(tokens, "manager")).json()
    names = {u["name"] for u in body["units"]}
    assert {"Dział IT", "Dział Finansów", "Biuro Obsługi Klienta"} <= names
    assert body["coverage"]["unknown_devices"] == 2
    assert len(body["trend"]) == 1
    www = next(u for u in body["units"] if u["name"] == "Zespół WWW")
    assert www["devices"] >= 3


@pytest.mark.usefixtures("org")
def test_manager_sees_names_and_view_is_audited(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    body = anon_client.get("/api/org/devices", headers=_as(tokens, "manager")).json()
    web = next(d for d in body["items"] if d["name"] == "web-01")
    assert web["owners"][0]["display_name"] == "Piotr Zieliński"
    assert web["unit"] == "Zespół WWW"
    # Menedżer nie widzi danych technicznych: nazwa segmentu zostaje, adres IP nie trafia.
    assert "172.30.99" not in str(body)
    entries = _audits(session_factory, "personal_data_viewed")
    assert len(entries) == 1
    assert "Zieliński" not in str(entries[0].inputs)


@pytest.mark.usefixtures("org")
def test_pseudonym_toggle_hides_names_and_skips_audit(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    body = anon_client.get(
        "/api/org/devices?pseudonyms=true", headers=_as(tokens, "manager")
    ).json()
    web = next(d for d in body["items"] if d["name"] == "web-01")
    assert web["owners"][0]["display_name"].startswith("Pracownik #")
    assert "Zieliński" not in str(body)
    assert _audits(session_factory, "personal_data_viewed") == []


@pytest.mark.usefixtures("org")
def test_auditor_without_personal_data_gets_pseudonyms(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    people = anon_client.get("/api/org/people", headers=_as(tokens, "auditor")).json()
    assert len(people) == 25
    assert all(p["display_name"].startswith("Pracownik #") for p in people)
    assert "Kowalczyk" not in str(people)


@pytest.mark.usefixtures("org")
def test_unknown_filter_lists_shadow_devices(anon_client: TestClient, tokens: TokenFactory) -> None:
    body = anon_client.get("/api/org/devices?unknown=true", headers=_as(tokens, "manager")).json()
    assert {d["name"] for d in body["items"]} == {"DESKTOP-7Q2KD1", "kamera-wifi-3f"}
    assert all(not d["in_cmdb"] for d in body["items"])


@pytest.mark.usefixtures("org")
def test_confirm_requires_write_and_closes_shadow_finding(
    anon_client: TestClient,
    client: TestClient,
    tokens: TokenFactory,
    session_factory: sessionmaker[Session],
) -> None:
    devices = client.get("/api/org/devices?unknown=true").json()["items"]
    camera = next(d for d in devices if d["name"] == "kamera-wifi-3f")
    manager = _as(tokens, "manager")
    assert (
        anon_client.post(f"/api/org/devices/{camera['id']}/confirm", headers=manager).status_code
        == 403
    )
    confirmed = client.post(f"/api/org/devices/{camera['id']}/confirm").json()
    assert confirmed["confirmed"] is True
    assert confirmed["status"] == "active"
    with session_factory() as session:
        finding = session.scalar(
            select(Finding).where(Finding.dedup_key == f"shadow:{camera['id']}")
        )
        assert finding is not None
        assert finding.status == "resolved"
    assert _audits(session_factory, "asset_confirmed")


def test_org_endpoints_require_login(anon_client: TestClient) -> None:
    assert anon_client.get("/api/org/overview").status_code == 401
