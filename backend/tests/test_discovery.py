"""Discovery: przebieg z fałszywym nmapem, porównanie, nadpisania, import i eksport."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.core.audit import DbAuditSink
from app.core.scope_guard import ScopeConfig, ScopedTarget, ScopeGuard
from app.discovery.engine import DiscoveryConfig, DiscoveryEngine, parse_targets
from app.discovery.fingerprint import HttpResult
from app.scanners.models import ServiceInfo
from app.scanners.nmap import NmapAdapter
from tests.conftest import FakeResolver
from tests.scanner_fakes import FakeLab

RULES = Path(__file__).resolve().parents[2] / "rules" / "discovery.yaml"


class FakeHttp:
    def probe(self, target: ScopedTarget, port: int, scheme: str) -> HttpResult:
        return HttpResult(
            url=f"{scheme}://{target.address}:{port}/",
            port=port,
            scheme=scheme,
            status=200,
            title="Panel administracyjny staging",
            headers={"server": "nginx/1.25"},
            technologies=["nginx"],
            paths={"/admin": 200},
        )


def _run(client: TestClient, factory: sessionmaker[Session], lab: FakeLab) -> str:
    response = client.post(
        "/api/discovery/runs", json={"items": ["10.10.0.0/24"], "settings": {"workers": 2}}
    )
    assert response.status_code == 202, response.text
    run_id = response.json()["id"]
    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.10.0.0/24"]}}),
        audit=DbAuditSink(factory),
        resolver=FakeResolver(),
    )
    engine_cfg = DiscoveryConfig.from_file(RULES)
    with factory() as session:
        run = DiscoveryEngine(
            session, guard, engine_cfg, nmap=NmapAdapter(lab.runner), fingerprinter=FakeHttp()
        ).run(uuid.UUID(run_id))
        assert run.status == "done", run.error
    return str(run_id)


def test_parse_targets_validates() -> None:
    parsed = parse_targets(["10.0.0.0/18", "example.test", "nie adres!", "10.0.0.5"])
    assert parsed.addresses == 16384 + 1  # domena liczona jako 1
    assert parsed.domains == ["example.test"]
    assert parsed.errors


def test_discovery_end_to_end(
    client: TestClient, session_factory: sessionmaker[Session], dispatcher: Any
) -> None:
    lab = FakeLab(
        {
            "10.10.0.5": [ServiceInfo(port=80, protocol="tcp", name="http", product="nginx")],
            "10.10.0.7": [ServiceInfo(port=22, protocol="tcp", name="ssh", product="OpenSSH")],
        }
    )
    first = _run(client, session_factory, lab)
    assert any(c[0] == "run_discovery" for c in dispatcher.calls)
    hosts = client.get(f"/api/discovery/runs/{first}/hosts").json()
    ips = {h["ip"]: h for h in (hosts["hosts"] if isinstance(hosts, dict) else hosts)}
    assert set(ips) == {"10.10.0.5", "10.10.0.7"}
    assert {f["kind"] for f in ips["10.10.0.5"]["flags"]} >= {"panel", "staging"}

    lab.services.pop("10.10.0.7")
    lab.services["10.10.0.9"] = [ServiceInfo(port=443, protocol="tcp", name="https")]
    second = _run(client, session_factory, lab)
    diff = client.get("/api/discovery/compare", params={"older": first, "newer": second}).json()
    assert [h["ip"] for h in diff["new_hosts"]] == ["10.10.0.9"]
    assert [h["ip"] for h in diff["gone_hosts"]] == ["10.10.0.7"]

    edit = client.put("/api/discovery/overrides/10.10.0.5", json={"field": "note", "value": "DMZ"})
    assert edit.status_code == 200, edit.text
    tagged = client.put(
        "/api/discovery/overrides/10.10.0.5",
        json={"field": "tags", "value": ["DMZ", " zespół-x ", "dmz"]},
    )
    assert tagged.status_code == 200, tagged.text
    third = _run(client, session_factory, lab)
    hosts = client.get(f"/api/discovery/runs/{third}/hosts").json()
    rows = hosts["hosts"] if isinstance(hosts, dict) else hosts
    host = next(h for h in rows if h["ip"] == "10.10.0.5")
    assert host["note"] == "DMZ"
    assert host["tags"] == ["dmz", "zespół-x"]
    assert "note" in host["edited"]

    csv = client.get(f"/api/discovery/runs/{third}/export", params={"format": "csv"})
    assert csv.status_code == 200
    assert "10.10.0.5" in csv.text
    xml = client.get(f"/api/discovery/runs/{third}/export", params={"format": "nmap"})
    assert "<nmaprun" in xml.text
    imported = client.post(
        "/api/discovery/import",
        json={"content": '[{"ip": "10.10.0.20", "services": [{"port": 8080}]}]', "name": "imp"},
    )
    assert imported.status_code in (200, 201), imported.text
    states = client.get("/api/discovery/states").json()
    assert states


def test_viewer_cannot_run_or_export_to_dojo(anon_client: TestClient, tokens: Any) -> None:
    anon_client.headers.update(tokens.headers(["viewer"], username="v"))
    assert anon_client.post("/api/discovery/runs", json={"items": ["10.10.0.1"]}).status_code == 403
    assert anon_client.get("/api/discovery/runs").status_code == 200


SIGNATURE = """
id: intranet-portal
name: Portal intranetowy
kind: panel
match:
  - {type: title, pattern: "intranet"}
  - {type: path, path: /portal/version, status: [200], pattern: "build"}
"""


def test_custom_signatures_crud_validation_and_audit(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    listing = client.get("/api/discovery/signatures").json()
    assert {s["id"] for s in listing["builtin"]} >= {"gitea", "rabbitmq-management"}
    assert listing["custom"] == []

    ok = client.post("/api/discovery/signatures/check", json={"yaml": SIGNATURE})
    assert ok.status_code == 200, ok.text
    unsafe = SIGNATURE.replace("status: [200]", "status: [200], method: POST")
    assert client.post("/api/discovery/signatures/check", json={"yaml": unsafe}).status_code == 422
    builtin_id = SIGNATURE.replace("intranet-portal", "gitea")
    clash = client.put("/api/discovery/signatures/gitea", json={"yaml": builtin_id})
    assert clash.status_code == 409
    mismatch = client.put("/api/discovery/signatures/inny", json={"yaml": SIGNATURE})
    assert mismatch.status_code == 422

    saved = client.put("/api/discovery/signatures/intranet-portal", json={"yaml": SIGNATURE})
    assert saved.status_code == 200, saved.text
    custom = client.get("/api/discovery/signatures").json()["custom"]
    assert [c["id"] for c in custom] == ["intranet-portal"]

    # Własna sygnatura działa w przebiegu: silnik dołącza ją do wbudowanych.
    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.10.0.0/24"]}}),
        audit=DbAuditSink(session_factory),
        resolver=FakeResolver(),
    )
    with session_factory() as session:
        engine = DiscoveryEngine(session, guard, DiscoveryConfig.from_file(RULES))
        engine._load_custom_signatures()
        assert "intranet-portal" in {s.id for s in engine._signatures}
        assert "gitea" in {s.id for s in engine._signatures}

    assert client.delete("/api/discovery/signatures/intranet-portal").status_code == 204
    assert client.get("/api/discovery/signatures").json()["custom"] == []
    actions = [e["action"] for e in client.get("/api/audit-log").json()["items"]]
    assert {"signature_saved", "signature_deleted"} <= set(actions)


def test_viewer_cannot_change_signatures(anon_client: TestClient, tokens: Any) -> None:
    anon_client.headers.update(tokens.headers(["viewer"], username="v"))
    assert anon_client.get("/api/discovery/signatures").status_code == 200
    put = anon_client.put("/api/discovery/signatures/x1", json={"yaml": SIGNATURE})
    assert put.status_code == 403


def test_signature_test_on_stored_run(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    """Test sygnatury bez ruchu sieciowego: dopasowanie do zapisanych wyników przebiegu."""
    lab = FakeLab(
        {"10.10.0.5": [ServiceInfo(port=80, protocol="tcp", name="http", product="nginx")]}
    )
    run_id = _run(client, session_factory, lab)
    yaml_text = (
        "id: admin-nginx\nname: Panel za nginx\nkind: panel\nmatch:\n"
        "  - {type: header, name: server, pattern: nginx}\n"
        "  - {type: path, path: /admin, status: [200], pattern: Zaloguj}\n"
        "  - {type: html, pattern: 'login-form'}\n"
    )
    response = client.post("/api/discovery/signatures/test", json={"yaml": yaml_text})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["run"]["id"] == run_id
    assert body["services_checked"] >= 1
    assert body["hits"], body
    evidence = body["hits"][0]["evidence"]
    assert "nagłówek server" in evidence
    assert "/admin → 200" in evidence
    assert body["live_only"] == ["html", "path (wzorzec treści)"]

    miss = client.post(
        "/api/discovery/signatures/test",
        json={"id": "gitea", "run_id": run_id},
    ).json()
    assert miss["hits"] == []
    assert miss["signature"]["id"] == "gitea"
    assert client.post("/api/discovery/signatures/test", json={"id": "brak"}).status_code == 404
    assert client.post("/api/discovery/signatures/test", json={}).status_code == 422
    bad = client.post(
        "/api/discovery/signatures/test", json={"yaml": "id: x1\nkind: zly\nmatch: []"}
    )
    assert bad.status_code == 422
