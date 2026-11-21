"""Moduł 21 (§25.1): „Aktualny obraz”, świeżość danych i prośby o skanowanie."""

from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models import AuditLog, Notification, OrgUnit, ScanRequest, ScanRun
from app.models.base import utcnow
from app.reports.config import ReportsConfig
from app.reports.current import finish_scan_request, freshness
from tests.conftest import RecordingDispatcher, TokenFactory
from tests.pipeline_helpers import RULES

CONFIG = ReportsConfig.from_dir(RULES)


def _as(tokens: TokenFactory, role: str) -> dict[str, str]:
    return tokens.headers([role], username=f"{role}-1")


def test_freshness_labels_and_threshold(session: Session) -> None:
    assert CONFIG.freshness_hours == 24
    empty = freshness(session, CONFIG)
    assert empty.stale
    assert "Nie było jeszcze skanu" in empty.label()
    now = utcnow()
    session.add(ScanRun(trigger="manual", status="done", finished_at=now - timedelta(hours=2)))
    session.flush()
    fresh = freshness(session, CONFIG, now)
    assert not fresh.stale
    assert fresh.label() == "Dane ze skanu sprzed 2 godz."
    old = freshness(session, CONFIG, now + timedelta(days=3))
    assert old.stale
    assert "dni" in old.label()


def test_manager_creates_current_picture_without_scanning(
    anon_client: TestClient, tokens: TokenFactory, dispatcher: RecordingDispatcher
) -> None:
    manager = _as(tokens, "manager")
    first = anon_client.post("/api/reports/current", headers=manager)
    assert first.status_code == 201
    body = first.json()
    assert body["kind"] == "assessment"
    assert body["scope"]["on_demand"] is True
    assert "label" in body["scope"]["freshness"]
    # Bez skanu: w kolejce tylko „W skrócie” modelem, żadnego run_scan.
    assert [call[0] for call in dispatcher.calls] == ["generate_report_summary"]
    # Drugie kliknięcie w ciągu minuty zwraca ten sam raport.
    second = anon_client.post("/api/reports/current", headers=manager)
    assert second.status_code == 200
    assert second.json()["id"] == body["id"]
    inbox = anon_client.get("/api/inbox", headers=manager).json()
    assert inbox["items"][0]["id"] == body["id"]


def test_auditor_cannot_create_current_picture(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    assert (
        anon_client.post("/api/reports/current", headers=_as(tokens, "auditor")).status_code == 403
    )


def test_freshness_endpoint(anon_client: TestClient, tokens: TokenFactory) -> None:
    body = anon_client.get("/api/freshness", headers=_as(tokens, "manager")).json()
    assert body["stale"] is True
    assert body["threshold_hours"] == 24


def test_scan_request_flow_manager_asks_admin_approves(
    anon_client: TestClient,
    tokens: TokenFactory,
    dispatcher: RecordingDispatcher,
    session_factory: sessionmaker[Session],
) -> None:
    with session_factory() as session:
        unit = OrgUnit(name="Dział IT", external_id="ou-it")
        session.add(unit)
        session.commit()
        unit_id = str(unit.id)
    manager = _as(tokens, "manager")
    # Menedżer nie uruchamia skanu sam.
    assert anon_client.post("/api/scans", headers=manager).status_code == 403
    created = anon_client.post(
        "/api/scan-requests",
        headers=manager,
        json={"scope_kind": "unit", "scope_ref": unit_id, "reason": "Nowy serwer w dziale"},
    )
    assert created.status_code == 201
    request = created.json()
    assert request["status"] == "pending"
    assert request["scope_label"] == "dział: Dział IT"
    assert dispatcher.calls == []
    # Ta sama prośba drugi raz nie dubluje kolejki.
    again = anon_client.post(
        "/api/scan-requests", headers=manager, json={"scope_kind": "unit", "scope_ref": unit_id}
    )
    assert again.json()["id"] == request["id"]
    # Menedżer nie może zatwierdzić własnej prośby.
    decision = f"/api/scan-requests/{request['id']}/decision"
    assert anon_client.post(decision, headers=manager, json={"approve": True}).status_code == 403

    admin = tokens.headers(["admin"], username="admin")
    queue = anon_client.get("/api/scan-requests?status=pending", headers=admin).json()
    assert [r["id"] for r in queue] == [request["id"]]
    approved = anon_client.post(decision, headers=admin, json={"approve": True, "reason": "ok"})
    assert approved.json()["status"] == "approved"
    assert dispatcher.calls[-1][0] == "run_scan"
    assert str(dispatcher.calls[-1][1][-1]) == request["id"]
    # Drugi raz nie da się rozpatrzyć.
    assert anon_client.post(decision, headers=admin, json={"approve": False}).status_code == 409

    with session_factory() as session:
        run = ScanRun(trigger="manager_request", status="done", finished_at=utcnow())
        session.add(run)
        session.flush()
        finish_scan_request(session, uuid.UUID(request["id"]), run)
        session.commit()
        stored = session.get(ScanRequest, uuid.UUID(request["id"]))
        assert stored is not None
        assert stored.status == "done"
        note = session.scalar(select(Notification).where(Notification.rule_name == "prosba_o_skan"))
        assert note is not None
        assert note.payload["recipient"] == "user:manager-1"
        actions = set(session.scalars(select(AuditLog.action)))
        assert {"scan_requested", "scan_request_approved"} <= actions
    mine = anon_client.get("/api/scan-requests", headers=manager).json()
    assert mine[0]["status"] == "done"


def test_scan_request_validates_scope(anon_client: TestClient, tokens: TokenFactory) -> None:
    manager = _as(tokens, "manager")
    missing = anon_client.post("/api/scan-requests", headers=manager, json={"scope_kind": "unit"})
    assert missing.status_code == 422
    org = anon_client.post("/api/scan-requests", headers=manager, json={})
    assert org.json()["scope_label"] == "cała organizacja"
