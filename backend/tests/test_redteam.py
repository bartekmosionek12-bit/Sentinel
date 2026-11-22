"""Trzy warstwy skanowania i delegacje w IAM (docs/WARSTWY.md).

Sprawdzamy: domyślnie tylko administrator; delegacja daje warstwę konkretnej osobie na
konkretnej podsieci w oknie czasu; warstwy startują tylko z jawnego wywołania; warstwa 1 jest
deterministyczna i przechodzi przez scope_guard; warstwa 2 domyślnie bez modelu; grupy idą
do DefectDojo jako jeden finding na grupę; agent (warstwa 3) wymaga warstwy 3.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.agent.planner import Planner
from app.agent.service import AgentService
from app.core.audit import DbAuditSink
from app.core.scope_guard import ScopeConfig, ScopeGuard
from app.discovery.defectdojo import DojoClient
from app.explainer.providers import FakeProvider
from app.models import AuditLog, RedteamFinding, RedteamRun
from app.redteam.analysis import analyze
from app.redteam.engine import (
    ALLOWED_SCRIPTS,
    Layer1Config,
    Layer1Scanner,
    NucleiStep,
    parse_scan_xml,
)
from tests.conftest import FakeResolver, MemoryAudit, RecordingDispatcher, TokenFactory
from tests.scanner_fakes import FakeRunner, discovery_xml

RULES = Path(__file__).resolve().parents[2] / "rules" / "redteam.yaml"
NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def _headers(tokens: TokenFactory, role: str, name: str, **kw: Any) -> dict[str, str]:
    return tokens.headers([role], username=name, **kw)


def _admin(tokens: TokenFactory) -> dict[str, str]:
    return _headers(tokens, "administrator", "admin")


def _user_id(client: TestClient, tokens: TokenFactory, role: str, name: str) -> str:
    """Konto powstaje przy pierwszym wywołaniu API (jak po logowaniu przez Keycloak)."""
    assert client.get("/api/me", headers=_headers(tokens, role, name)).status_code == 200
    users = client.get("/api/iam/users", headers=_admin(tokens)).json()
    return next(u["id"] for u in users if u["username"] == name)


def _delegate(
    client: TestClient,
    tokens: TokenFactory,
    user_id: str,
    layer: int,
    scope: list[str],
    *,
    start: datetime | None = None,
    hours: int = 4,
) -> Any:
    start = start or datetime.now(UTC) - timedelta(minutes=5)
    return client.post(
        "/api/iam/delegations",
        json={
            "user_id": user_id,
            "layer": layer,
            "scope": scope,
            "valid_from": start.isoformat(),
            "valid_until": (start + timedelta(hours=hours)).isoformat(),
            "reason": "Test podsieci serwerowni",
        },
        headers=_admin(tokens),
    )


def _layer1(client: TestClient, headers: dict[str, str], targets: list[str]) -> Any:
    return client.post(
        "/api/redteam/layer1/runs",
        json={"targets": targets, "reason": "Przegląd podatności po zmianie"},
        headers=headers,
    )


# --- uprawnienia i delegacje -------------------------------------------------------------


def test_only_admin_has_layers_by_default(anon_client: TestClient, tokens: TokenFactory) -> None:
    for role in ("editor", "modifier", "viewer"):
        layers = anon_client.get("/api/redteam/layers", headers=_headers(tokens, role, role))
        assert [item["access"]["allowed"] for item in layers.json()] == [False, False, False]
        assert _layer1(anon_client, _headers(tokens, role, role), ["10.10.0.5"]).status_code == 403
        task = anon_client.post(
            "/api/agent/tasks", json={"command": "assessment"}, headers=_headers(tokens, role, role)
        )
        assert task.status_code == 403
    admin = anon_client.get("/api/redteam/layers", headers=_admin(tokens)).json()
    assert [(i["access"]["allowed"], i["access"]["via"]) for i in admin] == [(True, "rola")] * 3


def test_custom_role_cannot_hold_layer_permissions(client: TestClient) -> None:
    response = client.put(
        "/api/iam/roles/pentester", json={"permissions": ["scan:read", "redteam:layer1"]}
    )
    assert response.status_code == 422
    assert "redteam:layer1" in response.json()["detail"]


def test_delegation_grants_one_layer_on_one_subnet(
    anon_client: TestClient, tokens: TokenFactory, dispatcher: RecordingDispatcher
) -> None:
    editor_id = _user_id(anon_client, tokens, "editor", "ewa")
    ewa = _headers(tokens, "editor", "ewa")
    granted = _delegate(anon_client, tokens, editor_id, 1, ["10.10.0.0/28"])
    assert granted.status_code == 201, granted.text
    assert granted.json()["state"] == "aktywna"

    layers = anon_client.get("/api/redteam/layers", headers=ewa).json()
    assert layers[0]["access"] == {
        "allowed": True,
        "via": "delegacja",
        "scope": ["10.10.0.0/28"],
        "until": layers[0]["access"]["until"],
    }
    assert [layers[1]["access"]["allowed"], layers[2]["access"]["allowed"]] == [False, False]

    # W podsieci: przebieg w kolejce. Poza podsiecią delegacji: 403 i wpis w audycie.
    started = _layer1(anon_client, ewa, ["10.10.0.5", "10.10.0.8/30"])
    assert started.status_code == 202, started.text
    assert started.json()["via_delegation"] is True
    assert dispatcher.calls[-1][0] == "run_redteam_layer1"
    outside = _layer1(anon_client, ewa, ["10.10.0.200"])
    assert outside.status_code == 403
    assert "poza podsiecią delegacji" in outside.json()["detail"]
    # Warstwa 2 i agent nadal zablokowane.
    run_id = started.json()["id"]
    assert (
        anon_client.post(f"/api/redteam/runs/{run_id}/analysis", json={}, headers=ewa).status_code
        == 403
    )
    # Bez MFA delegacja nie działa (jak uprawnienia z roli).
    no_mfa = tokens.headers(["editor"], username="ewa", client="sentinel-dashboard")
    assert _layer1(anon_client, no_mfa, ["10.10.0.5"]).status_code == 403

    # Odwołanie działa od następnego żądania.
    revoked = anon_client.post(
        f"/api/iam/delegations/{granted.json()['id']}/revoke", json={}, headers=_admin(tokens)
    )
    assert revoked.json()["state"] == "odwołana"
    assert _layer1(anon_client, ewa, ["10.10.0.5"]).status_code == 403


def test_delegation_outside_window_does_not_work(
    anon_client: TestClient, tokens: TokenFactory
) -> None:
    editor_id = _user_id(anon_client, tokens, "editor", "piotr")
    future = datetime.now(UTC) + timedelta(days=1)
    row = _delegate(anon_client, tokens, editor_id, 1, ["10.10.0.0/24"], start=future)
    assert row.json()["state"] == "zaplanowana"
    assert (
        _layer1(anon_client, _headers(tokens, "editor", "piotr"), ["10.10.0.5"]).status_code == 403
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"scope": ["192.168.0.0/24"]}, "zakresie skanowania"),
        ({"scope": ["intranet.example"]}, "nie jest adres IP"),
        ({"hours": 24 * 31}, "30 dni"),
        ({"layer": 4}, ""),
    ],
)
def test_delegation_is_validated(
    anon_client: TestClient, tokens: TokenFactory, change: dict[str, Any], message: str
) -> None:
    editor_id = _user_id(anon_client, tokens, "editor", "ola")
    response = _delegate(
        anon_client,
        tokens,
        editor_id,
        change.get("layer", 1),
        change.get("scope", ["10.10.0.0/28"]),
        hours=change.get("hours", 4),
    )
    assert response.status_code == 422
    assert message in json.dumps(response.json(), ensure_ascii=False)


def test_only_admin_manages_delegations(anon_client: TestClient, tokens: TokenFactory) -> None:
    editor_id = _user_id(anon_client, tokens, "editor", "kuba")
    response = anon_client.post(
        "/api/iam/delegations",
        json={
            "user_id": editor_id,
            "layer": 1,
            "scope": ["10.10.0.0/28"],
            "valid_from": datetime.now(UTC).isoformat(),
            "valid_until": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "reason": "samodzielne nadanie",
        },
        headers=_headers(tokens, "editor", "kuba"),
    )
    assert response.status_code == 403


def test_delegation_is_audited(
    anon_client: TestClient, tokens: TokenFactory, session_factory: sessionmaker[Session]
) -> None:
    editor_id = _user_id(anon_client, tokens, "editor", "ania")
    row = _delegate(anon_client, tokens, editor_id, 2, ["10.10.0.0/28"]).json()
    anon_client.post(f"/api/iam/delegations/{row['id']}/revoke", json={}, headers=_admin(tokens))
    with session_factory() as session:
        actions = set(session.scalars(select(AuditLog.action)))
    assert {"layer_delegated", "layer_delegation_revoked"} <= actions


# --- warstwa 1: deterministyczny skan --------------------------------------------------

CERT = (
    '<script id="ssl-cert" output="Subject: commonName=lab.example&#xa;'
    'Issuer: commonName=lab.example&#xa;">'
    '<table key="subject"><elem key="commonName">lab.example</elem></table>'
    '<table key="validity"><elem key="notAfter">2025-01-01T00:00:00</elem></table></script>'
)
CIPHERS = (
    '<script id="ssl-enum-ciphers" output="&#xa;  TLSv1.0: &#xa;    ciphers: &#xa;'
    '  TLSv1.2: &#xa;    ciphers: &#xa;  least strength: C"/>'
)


def _host_xml(ip: str, ports: str) -> str:
    return (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports></host></nmaprun>'
    )


def _port(
    port: int, name: str, scripts: str = "", product: str = "", version: str = "", tunnel: str = ""
) -> str:
    attrs = f'name="{name}" product="{product}" version="{version}"'
    if tunnel:
        attrs += f' tunnel="{tunnel}"'
    return (
        f'<port protocol="tcp" portid="{port}"><state state="open"/>'
        f"<service {attrs}/>{scripts}</port>"
    )


LAB = {
    "10.10.0.5": _host_xml(
        "10.10.0.5",
        _port(443, "http", CERT + CIPHERS, "nginx", "1.18.0", tunnel="ssl")
        + _port(
            21, "ftp", '<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>'
        )
        + _port(6379, "redis", product="Redis key-value store"),
    ),
    "10.10.0.6": _host_xml(
        "10.10.0.6",
        _port(
            443,
            "https",
            CIPHERS
            + '<script id="http-security-headers" output="&#xa;  Strict_Transport_Security: '
            '&#xa;    HSTS not configured in HTTPS Server"/>',
            tunnel="ssl",
        )
        + _port(
            22,
            "ssh",
            '<script id="ssh2-enum-algos" output="  kex_algorithms: &#xa;'
            '      diffie-hellman-group1-sha1&#xa;"/>',
            "OpenSSH",
            "7.4",
        ),
    ),
}
NUCLEI_HIT = json.dumps(
    {
        "template-id": "git-config",
        "info": {"name": "Git Config - Detect", "severity": "medium"},
        "matched-at": "https://10.10.0.5:443/.git/config",
    }
)


class Lab:
    def __init__(self, *, nuclei: bool) -> None:
        self.nuclei = nuclei
        self.runner = FakeRunner(self._respond)

    def _respond(self, argv: tuple[str, ...]) -> str:
        if argv[0] == "nuclei":
            if not self.nuclei:
                from app.scanners.runner import ToolError

                raise ToolError("Brak narzędzia nuclei w tym kontenerze")
            return NUCLEI_HIT + "\n" if argv[-1].startswith("10.10.0.5") else ""
        if "-sn" in argv:
            return discovery_xml(sorted(LAB))
        return LAB.get(argv[-1], _host_xml(argv[-1], ""))


def _scan(session_factory: sessionmaker[Session], run_id: str, lab: Lab) -> RedteamRun:
    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.10.0.0/24"]}}),
        audit=DbAuditSink(session_factory),
        resolver=FakeResolver(),
    )
    with session_factory() as session:
        return Layer1Scanner(
            session, guard, Layer1Config.from_file(RULES), runner=lab.runner, now=NOW
        ).run(uuid.UUID(run_id))


def test_layer1_config_allows_only_safe_tools() -> None:
    config = Layer1Config.from_file(RULES)
    assert set(config.scripts) <= ALLOWED_SCRIPTS
    with pytest.raises(ValueError, match="spoza listy"):
        Layer1Config.from_dict({"scripts": ["http-shellshock"], "ports": "80"})
    with pytest.raises(ValueError, match="niedozwolone tagi"):
        NucleiStep.from_dict({"enabled": True, "tags": ["cve", "sqli"]})
    args = config.nuclei.args()
    excluded = args[args.index("-etags") + 1].split(",")
    assert {"exploit", "rce", "sqli", "bruteforce", "dos", "default-login"} <= set(excluded)


def test_layer1_finds_and_groups_vulnerabilities(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    started = _layer1(client, {}, ["10.10.0.0/29"])
    assert started.status_code == 202, started.text
    run = _scan(session_factory, started.json()["id"], Lab(nuclei=True))
    assert run.status == "done", run.error

    detail = client.get(f"/api/redteam/runs/{run.id}").json()
    groups = {g["group_key"]: g for g in detail["groups"]}
    # Ten sam problem na dwóch hostach to jedna grupa.
    assert groups["tls_old_protocol"]["count"] == 2
    assert groups["tls_old_protocol"]["unique_hosts"] == 2
    assert {
        "tls_weak_cipher",
        "cert_expired",
        "cert_self_signed",
        "ftp_anonymous",
        "cleartext_ftp",
        "exposed_datastore",
        "ssh_weak_algorithms",
        "outdated_software:openssh",
        "outdated_software:nginx",
        "http_missing_hsts",
        "nuclei:git-config",
    } <= set(groups)
    # Grupy posortowane od najpoważniejszych.
    ranks = ["critical", "high", "medium", "low", "info"]
    order = [ranks.index(g["severity"]) for g in detail["groups"]]
    assert order == sorted(order)
    assert detail["summary"]["groups"] == len(groups)
    # Log narzędzi dla warstwy 2: polecenie i surowe wyjście skryptów.
    scans = [e for e in detail["log"] if e.get("step") == "skan"]
    assert {e["target"] for e in scans} == {"10.10.0.5", "10.10.0.6"}
    assert any("ssl-enum-ciphers" in key for e in scans for key in e["scripts"])
    # Warstwa 1 nie zleca sama warstwy 2.
    assert detail["analysis"] is None

    latest = client.get("/api/redteam/latest").json()
    assert latest["id"] == str(run.id)


def test_layer1_is_deterministic_and_goes_through_scope_guard(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    results = []
    for _ in range(2):
        run_id = _layer1(client, {}, ["10.10.0.0/29"]).json()["id"]
        _scan(session_factory, run_id, Lab(nuclei=True))
        with session_factory() as session:
            results.append(
                sorted(
                    (f.group_key, f.ip, f.port, tuple(f.evidence))
                    for f in session.scalars(
                        select(RedteamFinding).where(RedteamFinding.run_id == uuid.UUID(run_id))
                    )
                )
            )
    assert results[0] == results[1]
    with session_factory() as session:
        rules = set(
            session.scalars(select(AuditLog.actor).where(AuditLog.actor.like("rule:redteam%")))
        )
    assert {
        "rule:redteam_layer1",
        "rule:redteam_layer1_nuclei",
        "rule:redteam_layer1_discovery",
    } <= rules


def test_layer1_without_nuclei_binary_says_so(
    client: TestClient, session_factory: sessionmaker[Session]
) -> None:
    run_id = _layer1(client, {}, ["10.10.0.5"]).json()["id"]
    run = _scan(session_factory, run_id, Lab(nuclei=False))
    assert run.status == "done"
    entry = next(e for e in run.log if e.get("target") == "10.10.0.5")
    assert "nuclei pominięty" in entry["nuclei"][0]["skipped"]
    assert not any(
        k.startswith("nuclei:")
        for k in (
            g["group_key"] for g in client.get(f"/api/redteam/runs/{run_id}").json()["groups"]
        )
    )


def test_layer1_rejects_targets_outside_scan_scope(client: TestClient) -> None:
    response = _layer1(client, {}, ["192.168.1.0/24"])
    assert response.status_code == 422
    assert "poza zakresem skanowania" in json.dumps(response.json(), ensure_ascii=False)
    assert _layer1(client, {}, ["intranet.example"]).status_code == 422


def test_parse_scan_xml_keeps_script_elements() -> None:
    ports = parse_scan_xml(LAB["10.10.0.5"])["10.10.0.5"]
    https = next(p for p in ports if p.port == 443)
    assert https.elems["ssl-cert"]["notAfter"] == ["2025-01-01T00:00:00"]
    assert https.tunnel == "ssl"


# --- warstwa 2 -----------------------------------------------------------------------


@pytest.fixture
def finished_run(client: TestClient, session_factory: sessionmaker[Session]) -> str:
    run_id = _layer1(client, {}, ["10.10.0.0/29"]).json()["id"]
    run = _scan(session_factory, run_id, Lab(nuclei=True))
    assert run.status == "done", (run.error, run.log)
    return str(run_id)


def _analysis(
    client: TestClient,
    session_factory: sessionmaker[Session],
    dispatcher: RecordingDispatcher,
    run_id: str,
    provider: FakeProvider | None,
) -> dict[str, Any]:
    requested = client.post(f"/api/redteam/runs/{run_id}/analysis", json={})
    assert requested.status_code == 202, requested.text
    assert dispatcher.calls[-1][0] == "analyze_redteam"
    with session_factory() as session:
        analyze(session, dispatcher.calls[-1][1][0], provider)
    return client.get(f"/api/redteam/runs/{run_id}/analysis").json()


def test_layer2_without_model_uses_labelled_template(
    client: TestClient,
    session_factory: sessionmaker[Session],
    dispatcher: RecordingDispatcher,
    finished_run: str,
) -> None:
    result = _analysis(client, session_factory, dispatcher, finished_run, None)
    assert result["status"] == "done"
    assert result["source"] == "template"
    assert result["model"] is None
    assert "REDTEAM_LLM=off" in result["content"]["problems"][0]
    tls = next(g for g in result["content"]["groups"] if g["group_key"] == "tls_old_protocol")
    assert "TLS 1.2" in " ".join(tls["steps"])
    assert result["content"]["strategy"]


def test_layer2_model_gets_anonymized_logs_and_is_validated(
    client: TestClient,
    session_factory: sessionmaker[Session],
    dispatcher: RecordingDispatcher,
    finished_run: str,
) -> None:
    answer = {
        "summary": "Najpierw Redis i anonimowy FTP.",
        "groups": [
            {
                "group_key": "exposed_datastore",
                "risk": "Dostęp bez hasła",
                "steps": ["Zamknij port 6379 zaporą"],
                "effort": "niski",
            },
            {"group_key": "wymyslona_grupa", "risk": "x", "steps": ["y"]},
        ],
        "strategy": ["1. Redis", "2. FTP"],
    }
    model = FakeProvider([json.dumps(answer, ensure_ascii=False)])
    result = _analysis(client, session_factory, dispatcher, finished_run, model)
    assert result["source"] == "model"
    prompt = model.prompts[0]
    # Adresy IP nie trafiają do modelu; schemat odpowiedzi jest wymuszony.
    assert "10.10.0.5" not in prompt.user
    assert "ip_" in prompt.user
    assert prompt.schema is not None
    groups = {g["group_key"]: g for g in result["content"]["groups"]}
    assert groups["exposed_datastore"]["source"] == "model"
    assert "wymyslona_grupa" not in groups
    assert groups["ftp_anonymous"]["source"] == "template"
    assert any("spoza wyników" in p for p in result["content"]["problems"])


def test_layer2_needs_finished_layer1_and_permission(
    client: TestClient, anon_client: TestClient, tokens: TokenFactory, finished_run: str
) -> None:
    viewer = _headers(tokens, "viewer", "wiktor")
    assert (
        anon_client.post(
            f"/api/redteam/runs/{finished_run}/analysis", json={}, headers=viewer
        ).status_code
        == 403
    )
    queued = _layer1(client, {}, ["10.10.0.5"]).json()["id"]
    assert client.post(f"/api/redteam/runs/{queued}/analysis", json={}).status_code == 409
    # Odczyt wyników ma każdy z `findings:read`.
    assert anon_client.get(f"/api/redteam/runs/{finished_run}", headers=viewer).status_code == 200


# --- DefectDojo ----------------------------------------------------------------------


def test_groups_go_to_defectdojo_once(
    client: TestClient,
    session_factory: sessionmaker[Session],
    dispatcher: RecordingDispatcher,
    finished_run: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[tuple[list[dict[str, Any]], str]] = []

    def fake_import(self: DojoClient, findings: list[dict[str, Any]], *, test_title: str) -> dict:
        sent.append((findings, test_title))
        return {"test": 7, "engagement": 3, "product": 1}

    monkeypatch.setattr(DojoClient, "import_findings", fake_import)
    _analysis(client, session_factory, dispatcher, finished_run, None)
    first = client.post(f"/api/redteam/runs/{finished_run}/defectdojo").json()
    groups = client.get(f"/api/redteam/runs/{finished_run}").json()["groups"]
    assert first["sent"] == len(groups)
    findings = sent[0][0]
    tls = next(f for f in findings if f["vuln_id_from_tool"].endswith(":tls_old_protocol"))
    assert tls["severity"] == "Medium"
    assert len(tls["endpoints"]) == 2  # jeden finding, dwa punkty końcowe
    assert "TLS 1.2" in tls["mitigation"]  # zalecenie z warstwy 2
    again = client.post(f"/api/redteam/runs/{finished_run}/defectdojo").json()
    assert again["sent"] == 0


# --- warstwa 3: agent --------------------------------------------------------------------


def test_agent_needs_layer3_and_delegated_subnet(
    anon_client: TestClient,
    tokens: TokenFactory,
    dispatcher: RecordingDispatcher,
    session_factory: sessionmaker[Session],
    tmp_path: Path,
) -> None:
    from tests.test_api_agent import SCOPE, _activate_via_api

    _activate_via_api(anon_client, tokens, session_factory, tmp_path)
    editor_id = _user_id(anon_client, tokens, "editor", "marek")
    marek = _headers(tokens, "editor", "marek")
    command = {"command": "Zbierz pakiety przez SSH z 10.10.0.5"}
    assert anon_client.post("/api/agent/tasks", json=command, headers=marek).status_code == 403

    # Delegacja warstwy 3 na innej podsieci: zadanie przyjęte, ale zgoda na krok poza nią nie.
    _delegate(anon_client, tokens, editor_id, 3, ["10.10.0.128/25"])
    created = anon_client.post("/api/agent/tasks", json=command, headers=marek)
    assert created.status_code == 202, created.text
    task_id = uuid.UUID(created.json()["id"])
    with session_factory() as session:
        guard = ScopeGuard(
            ScopeConfig.from_dict(SCOPE), audit=MemoryAudit(), resolver=FakeResolver()
        )
        AgentService(session, guard, Planner(None)).plan_task(task_id)
    approve = anon_client.post(
        f"/api/agent/tasks/{task_id}/approve", json={"reason": "zgoda"}, headers=marek
    )
    assert approve.status_code == 403
    assert "poza podsiecią delegacji" in approve.json()["detail"]

    _delegate(anon_client, tokens, editor_id, 3, ["10.10.0.0/28"])
    approve = anon_client.post(
        f"/api/agent/tasks/{task_id}/approve", json={"reason": "zgoda"}, headers=marek
    )
    assert approve.status_code == 202, approve.text


def test_non_human_identities(client: TestClient) -> None:
    data = client.get("/api/iam/non-human").json()
    assert {r["name"] for r in data["roles"]} == {"agent", "system"}
    assert all(r["permissions"] == [] for r in data["roles"])
    assert data["agent"]["layer"] == 3


def test_layers_never_start_by_themselves(dispatcher: RecordingDispatcher) -> None:
    """Brak zadań okresowych dla warstw: tylko ręczne wywołanie przez API."""
    from app.workers.celery_app import celery_app

    scheduled = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    # Okresowy jest tylko test bezpieczeństwa agenta (moduł 19), nie jego zadania.
    starts = {"app.workers.tasks.agent.plan_task", "app.workers.tasks.agent.execute_task"}
    assert not {t for t in scheduled if "redteam" in t or t in starts}
