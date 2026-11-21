"""API: zasoby, audit log i podgląd decyzji scope_guard (bez sieci)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.inventory.service import asset_fingerprint
from app.models import Asset
from app.scanners.nmap import parse_nmap_xml


def test_openapi_is_served(client: TestClient) -> None:
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert "/api/assets" in response.json()["paths"]
    assert client.get("/api/sprint/dashboard").json()["recent_runs"] == []


def test_create_and_list_assets(client: TestClient) -> None:
    payload = {"type": "host", "name": "web-01.example.lab", "exposure": "internet"}
    created = client.post("/api/assets", json=payload)
    assert created.status_code == 201
    body = created.json()
    assert body["criticality"] == 3
    assert body["status"] == "active"

    listing = client.get("/api/assets", params={"type": "host"}).json()
    assert listing["total"] == 1
    assert listing["items"][0]["name"] == "web-01.example.lab"
    assert client.get(f"/api/assets/{body['id']}").status_code == 200


def test_duplicate_asset_is_rejected(client: TestClient) -> None:
    payload = {"type": "host", "name": "web-01.example.lab"}
    assert client.post("/api/assets", json=payload).status_code == 201
    duplicate = client.post("/api/assets", json={**payload, "name": "WEB-01.example.lab."})
    assert duplicate.status_code == 409


def test_invalid_asset_is_rejected(client: TestClient) -> None:
    assert client.post("/api/assets", json={"type": "printer", "name": "x"}).status_code == 422
    bad = {"type": "host", "name": "x", "criticality": 9}
    assert client.post("/api/assets", json=bad).status_code == 422


def test_scan_targets_and_result_import_export_override(client: TestClient) -> None:
    targets = client.post(
        "/api/scan-targets/preview", json={"format": "manual", "text": "10.10.0.5\n8.8.8.8"}
    )
    assert targets.status_code == 200
    assert len(targets.json()["targets"]) == 1
    assert len(targets.json()["errors"]) == 1
    saved = client.post("/api/scan-targets", json={"format": "csv", "text": "target\n10.10.0.5\n"})
    assert saved.json()["added"] == 1
    assert client.get("/api/scan-targets").json()[0]["target"] == "10.10.0.5"

    result_json = (
        '{"hosts":[{"ip":"10.10.0.5","services":'
        '[{"port":80,"product":"nginx","version":"1.0"}]}]}'
    )
    imported = client.post(
        "/api/scan-results/import",
        json={"format": "json", "text": result_json},
    )
    assert imported.status_code == 200
    run_id = imported.json()["run_id"]
    assert client.get(f"/api/scan-results/{run_id}").json()["hosts"]["10.10.0.5"]["services"]
    changed = client.post(
        "/api/scan-results/override",
        json={"host": "10.10.0.5", "field": "note", "value": "Sprawdzone ręcznie"},
    )
    assert changed.status_code == 200
    data = client.get(f"/api/scan-results/{run_id}").json()["hosts"]["10.10.0.5"]
    assert data["manually_changed"]
    assert data["note"] == "Sprawdzone ręcznie"
    assert client.get(f"/api/scan-results/{run_id}/export?format=csv").status_code == 200
    xml = client.get(f"/api/scan-results/{run_id}/nmap.xml")
    assert xml.status_code == 200
    assert parse_nmap_xml(xml.text)[0].ip == "10.10.0.5"


def test_asset_creation_is_audited(client: TestClient) -> None:
    client.post("/api/assets", json={"type": "host", "name": "db-01"})
    log = client.get("/api/audit-log").json()
    assert log["total"] == 1
    entry = log["items"][0]
    assert entry["action"] == "asset_created"
    assert entry["inputs"]["name"] == "db-01"
    assert client.get("/api/audit-log/verify").json() == {
        "ok": True,
        "entries": 1,
        "broken_at_id": None,
        "detail": None,
    }


def test_scope_check_allows_and_denies_and_audits(client: TestClient) -> None:
    allowed = client.post("/api/scope/check", json={"target": "10.10.0.5"}).json()
    assert allowed["allowed"] is True
    assert allowed["resolved_ip"] == "10.10.0.5"

    denied = client.post("/api/scope/check", json={"target": "8.8.8.8"}).json()
    assert denied["allowed"] is False
    assert denied["decision"] == "scope_denied"

    needs_approval = client.post(
        "/api/scope/check", json={"target": "10.10.0.5", "intrusiveness": 2}
    ).json()
    assert needs_approval["decision"] == "scope_awaiting_approval"

    actions = [e["action"] for e in client.get("/api/audit-log").json()["items"]]
    assert actions == ["scope_awaiting_approval", "scope_denied", "scope_allowed"]
    assert client.get("/api/audit-log", params={"action": "scope_denied"}).json()["total"] == 1


def test_scope_endpoint_reports_configuration(client: TestClient) -> None:
    scope = client.get("/api/scope").json()
    assert scope["allowed_cidrs"] == ["10.10.0.0/24"]
    assert scope["demo_mode"] is False


def test_assets_list_shows_device_types_from_org_sources(
    client: TestClient, session: Session
) -> None:
    """Urządzenia z AD, MDM i CMDB (np. `network`) nie mogą psuć listy zasobów (HTTP 500)."""
    session.add(
        Asset(
            type="network",
            name="switch-core-01",
            exposure="internal",
            fingerprint=asset_fingerprint("network", "switch-core-01"),
        )
    )
    session.commit()
    listing = client.get("/api/assets", params={"limit": 500})
    assert listing.status_code == 200
    assert [item["type"] for item in listing.json()["items"]] == ["network"]
    assert client.get("/api/assets", params={"type": "network"}).json()["total"] == 1
    # Ręcznie i z CSV nadal tylko typy zasobów, nie urządzeń.
    assert client.post("/api/assets", json={"type": "network", "name": "x"}).status_code == 422
