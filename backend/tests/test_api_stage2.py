"""API Etapu 2 na pełnej ścieżce: import, feedy, skan, findingi, decyzje człowieka."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import get_dispatcher, get_rulebook, get_scope_guard
from app.core.audit import DbAuditSink
from app.core.scope_guard import ScopeConfig, ScopeGuard
from app.feeds.base import OfflineSource
from app.feeds.service import sync_all
from app.pipeline import Rulebook
from app.scanners.models import ServiceInfo
from app.scanners.nmap import NmapAdapter
from app.scans.service import ScanService
from tests.conftest import FakeResolver
from tests.pipeline_helpers import ASSETS_CSV, FEEDS_DIR, RULES, SERVICES
from tests.scanner_fakes import FakeLab

RULEBOOK = Rulebook.from_dir(RULES)


class InlineDispatcher:
    """Zamiast Celery wykonuje zadania od razu, na udawanej sieci demo-lab."""

    def __init__(self, factory: sessionmaker[Session], guard: ScopeGuard, lab: FakeLab) -> None:
        self._factory = factory
        self._guard = guard
        self._lab = lab

    def _service(self, session: Session) -> ScanService:
        return ScanService(session, self._guard, RULEBOOK, nmap=NmapAdapter(self._lab.runner))

    def run_scan(self, actor: str) -> str:
        with self._factory() as session:
            self._service(session).run(trigger="manual", actor=actor)
        return "task-scan"

    def approve_action(self, action_id: uuid.UUID, approved_by: str, reason: str) -> str:
        with self._factory() as session:
            self._service(session).approve(action_id, approved_by=approved_by, reason=reason)
        return "task-approve"

    def sync_feeds(self, actor: str) -> str:
        with self._factory() as session:
            sync_all(session, OfflineSource(FEEDS_DIR), actor=actor)
            session.commit()
        return "task-feeds"


@pytest.fixture
def lab() -> FakeLab:
    lab = FakeLab(SERVICES)
    lab.extra_ports["172.30.99.10"] = (
        ServiceInfo(16379, "tcp", "redis", "Redis key-value store", "5.0.7"),
    )
    return lab


@pytest.fixture
def api(client: TestClient, session_factory: sessionmaker[Session], lab: FakeLab) -> TestClient:
    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["172.30.99.0/24"]}}),
        audit=DbAuditSink(session_factory),
        resolver=FakeResolver(),
    )
    overrides = client.app.dependency_overrides  # type: ignore[attr-defined]
    overrides[get_scope_guard] = lambda: guard
    overrides[get_rulebook] = lambda: RULEBOOK
    overrides[get_dispatcher] = lambda: InlineDispatcher(session_factory, guard, lab)
    return client


def _seed(api: TestClient) -> None:
    imported = api.post("/api/assets/import", json={"csv": ASSETS_CSV})
    assert imported.status_code == 200
    assert imported.json()["created"] == 3
    assert api.post("/api/feeds/sync").status_code == 202
    assert api.post("/api/scans").status_code == 202


def _json(api: TestClient, url: str) -> Any:
    response = api.get(url)
    assert response.status_code == 200, response.text
    return response.json()


def test_critical_path_from_import_to_prioritised_findings(api: TestClient) -> None:
    _seed(api)
    findings = _json(api, "/api/findings")
    assert findings["total"] == 3
    top = findings["items"][0]
    assert top["vulnerability"]["cve_id"] == "CVE-2021-42013"
    assert (top["risk_level"], top["asset"]["name"]) == ("krytyczny", "web-01")
    assert top["summary"].startswith("Krytyczny, bo: ")
    scores = [f["risk_score"] for f in findings["items"]]
    assert scores == sorted(scores, reverse=True)
    assert _json(api, "/api/findings?kev=true")["total"] == 2
    assert _json(api, "/api/findings?level=niski")["total"] == 1

    detail = _json(api, f"/api/findings/{top['id']}")
    assert [c["name"] for c in detail["risk_breakdown"]["components"]] == [
        "cvss",
        "epss",
        "kev",
        "exposure",
        "criticality",
        "exploit",
    ]
    assert detail["evidence"]["affected_range"] == "= 2.4.49"
    assert detail["events"][0]["kind"] == "created"
    assert detail["kev_required_action"]

    stats = _json(api, "/api/stats")
    assert stats["findings_active"] == 3
    assert stats["findings_by_level"]["krytyczny"] == 2
    assert stats["kev_active"] == 2
    assert stats["review_queue"] == 1
    assert stats["awaiting_approval"] == 1
    assert stats["last_scan"]["status"] == "done"
    assert {f["feed"]: f["status"] for f in stats["feeds"]} == {
        "nvd": "ok",
        "kev": "ok",
        "epss": "ok",
    }
    assert _json(api, "/api/audit-log/verify")["ok"]


def test_threat_feed_separates_what_affects_us_from_everything(api: TestClient) -> None:
    _seed(api)
    ours = _json(api, "/api/threat-feed")
    assert (ours["total"], ours["total_ours"]) == (9, 3)
    assert (ours["new_total"], ours["new_ours"]) == (9, 3)
    assert [t["cve_id"] for t in ours["items"]] == [
        "CVE-2021-42013",
        "CVE-2021-41773",
        "CVE-2021-23017",
    ]
    assert ours["items"][0]["affected_assets"][0]["asset_name"] == "web-01"
    everything = _json(api, "/api/threat-feed?scope=all")
    assert len(everything["items"]) == 9
    log4j = next(t for t in everything["items"] if t["cve_id"] == "CVE-2021-44228")
    assert log4j["affected_assets"] == []
    assert log4j["max_risk"] is None


def test_review_queue_decision_creates_findings_only_after_acceptance(api: TestClient) -> None:
    _seed(api)
    (item,) = _json(api, "/api/review-queue")
    assert item["asset"]["name"] == "legacy-01"
    assert item["software"]["version"] == "2.4.25"
    assert "pakiet dystrybucji" in item["reason"]
    assert _json(api, f"/api/findings?asset_id={item['asset']['id']}")["total"] == 0

    decided = api.post(f"/api/review-queue/{item['id']}/decision", json={"accept": True})
    assert decided.status_code == 200
    assert decided.json() == {"match_status": "confirmed", "findings_created": 3}
    assert _json(api, f"/api/findings?asset_id={item['asset']['id']}")["total"] == 3
    assert _json(api, "/api/review-queue") == []
    again = api.post(f"/api/review-queue/{item['id']}/decision", json={"accept": False})
    assert again.status_code == 409


def test_finding_status_change_needs_reason_for_risk_acceptance(api: TestClient) -> None:
    _seed(api)
    finding = _json(api, "/api/findings")["items"][0]
    url = f"/api/findings/{finding['id']}"
    assert api.patch(url, json={"status": "accepted_risk"}).status_code == 422
    assert api.patch(url, json={"status": "nonsense"}).status_code == 422
    done = api.patch(
        url,
        json={"status": "accepted_risk", "reason": "System wyłączany w grudniu"},
    )
    assert done.status_code == 200
    body = done.json()
    assert body["status"] == "accepted_risk"
    assert body["events"][0]["kind"] == "status_changed"
    assert body["events"][0]["actor"] == "user:admin"
    assert _json(api, "/api/findings")["total"] == 2
    assert _json(api, "/api/findings?status=all")["total"] == 3
    assert _json(api, "/api/findings?status=accepted_risk")["total"] == 1
    assigned = api.patch(url, json={"assignee": "jan"})
    assert assigned.json()["assignee"] == "jan"
    assert assigned.json()["events"][0]["kind"] == "assigned"
    assert api.patch(f"/api/findings/{uuid.uuid4()}", json={}).status_code == 404
    assert api.get(f"/api/findings/{uuid.uuid4()}").status_code == 404


def test_intrusive_action_waits_for_approval_then_runs(api: TestClient, lab: FakeLab) -> None:
    _seed(api)
    (action,) = _json(api, "/api/scan-actions?status=awaiting_approval")
    assert (action["rule_name"], action["intrusiveness"]) == ("kev_full_port_scan", 2)
    assert not any("1-65535" in call for call in lab.runner.calls)
    url = f"/api/scan-actions/{action['id']}"
    assert api.post(f"{url}/approve", json={"reason": ""}).status_code == 422

    approved = api.post(f"{url}/approve", json={"reason": "Okno serwisowe"})
    assert approved.status_code == 202
    assert any("1-65535" in call for call in lab.runner.calls)
    (done,) = [a for a in _json(api, "/api/scan-actions") if a["id"] == action["id"]]
    assert (done["status"], done["approval_source"]) == ("done", "human:admin")
    assert _json(api, "/api/findings")["total"] == 4
    assert api.post(f"{url}/approve", json={"reason": "abc"}).status_code == 409
    assert (
        api.post(f"/api/scan-actions/{uuid.uuid4()}/reject", json={"reason": "abc"}).status_code
        == 404
    )


def test_rejected_intrusive_action_is_never_executed(api: TestClient, lab: FakeLab) -> None:
    _seed(api)
    (action,) = _json(api, "/api/scan-actions?status=awaiting_approval")
    rejected = api.post(f"/api/scan-actions/{action['id']}/reject", json={"reason": "Nie teraz"})
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "denied"
    assert not any("1-65535" in call for call in lab.runner.calls)
    runs = _json(api, "/api/scans")
    assert runs[0]["actions"][-1]["scope_decision"] == "rejected_by_human"


def test_asset_details_notifications_and_csv_errors(api: TestClient) -> None:
    _seed(api)
    web = next(a for a in _json(api, "/api/assets")["items"] if a["name"] == "web-01")
    details = _json(api, f"/api/assets/{web['id']}/details")
    assert details["attributes"]["open_ports"] == [80]
    assert details["software"][0]["match_status"] == "auto"
    assert [h["change"] for h in details["history"]] == ["scanned", "imported"]
    assert details["active_findings"] == 2
    assert api.get(f"/api/assets/{uuid.uuid4()}/details").status_code == 404

    (notification,) = _json(api, "/api/notifications")
    assert notification["rule_name"] == "kev_na_zasobie_z_internetu"
    assert notification["payload"]["asset_name"] == "web-01"

    bad = api.post("/api/assets/import", json={"csv": "name,type\nx,router\n"})
    assert bad.json() == {
        "created": 0,
        "updated": 0,
        "unchanged": 0,
        "errors": ["Wiersz 2: nieznany typ 'router'"],
    }
