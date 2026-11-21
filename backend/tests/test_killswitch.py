"""Kill switch od początku do końca: flaga, Keycloak, OpenBao i zatrzymanie `mcp-scanner`.

Keycloak i OpenBao są tu prawdziwymi klientami HTTP z kodu aplikacji, a odpowiedzi daje
`httpx.MockTransport`, który sprawdza dokładne ścieżki admin API. Trwające wywołanie to
prawdziwy proces (atrapa `nmap`, która śpi), zabijany przez strażnika kill switcha. Na żywo
te same trzy skutki sprawdza `scripts/check_killswitch.py` w CI (demo-lab, Keycloak, OpenBao).
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.agent.gateway import LocalGateway
from app.agent.killswitch import (
    CERT_GAP,
    FakeEffect,
    KeycloakClientSwitch,
    OpenBaoLeaseRevoker,
    run_effects,
)
from app.agent.planner import Planner
from app.agent.service import AgentService, activate_capability, create_capability
from app.core.scope_guard import ScopeConfig, ScopeGuard
from app.credentials.openbao import FakeVault
from app.iam.tokens import Principal
from app.mcp_server.runtime import Toolbox, ToolRuntime
from app.mcp_server.server import AgentTokenVerifier
from app.mcp_server.watcher import KillWatcher
from app.models import AgentStep, AgentSwitch, AgentTask, AuditLog
from app.scanners.http_probe import HttpProber
from app.scanners.nmap import NmapAdapter
from app.scanners.runner import Cancellations, SubprocessRunner
from tests.conftest import FakeResolver, MemoryAudit

SCOPE = {"allow": {"cidrs": ["172.30.99.0/24"]}, "deny": {"cidrs": ["172.30.99.1/32"]}}


class FakeKeycloak:
    """Admin API Keycloaka w zakresie, którego używa kill switch."""

    def __init__(self) -> None:
        self.enabled = True
        self.requests: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        path = request.url.path
        if path.endswith("/protocol/openid-connect/token"):
            assert request.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"access_token": "kc-admin", "expires_in": 60})
        assert request.headers["authorization"] == "Bearer kc-admin"
        if request.method == "GET" and path.endswith("/admin/realms/sentinel/clients"):
            assert request.url.params["clientId"] == "sentinel-agent"
            return httpx.Response(
                200, json=[{"id": "c-1", "clientId": "sentinel-agent", "enabled": self.enabled}]
            )
        if request.method == "PUT" and path.endswith("/admin/realms/sentinel/clients/c-1"):
            self.enabled = bool(json.loads(request.content)["enabled"])
            return httpx.Response(204)
        return httpx.Response(404)


class FakeBao:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.revoked_prefixes: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        path = request.url.path
        if path == "/v1/auth/killswitch/login":
            body = json.loads(request.content)
            assert body == {"role_id": "kill-role", "secret_id": "kill-secret"}
            return httpx.Response(200, json={"auth": {"client_token": "bao-kill"}})
        assert request.headers["x-vault-token"] == "bao-kill"
        if request.method == "PUT" and path.startswith("/v1/sys/leases/revoke-prefix/"):
            self.revoked_prefixes.append(path.removeprefix("/v1/sys/leases/revoke-prefix/"))
            return httpx.Response(204)
        if path == "/v1/auth/token/revoke-self":
            return httpx.Response(204)
        return httpx.Response(404)


def _keycloak(fake: FakeKeycloak) -> KeycloakClientSwitch:
    return KeycloakClientSwitch(
        base_url="http://keycloak:8080/auth",
        realm="sentinel",
        client_id="sentinel-killswitch",
        client_secret="kill-secret",
        target_client_id="sentinel-agent",
        client=httpx.Client(transport=httpx.MockTransport(fake)),
    )


def _openbao(fake: FakeBao) -> OpenBaoLeaseRevoker:
    return OpenBaoLeaseRevoker(
        url="http://openbao:8200",
        role_id="kill-role",
        secret_id="kill-secret",
        client=httpx.Client(transport=httpx.MockTransport(fake)),
    )


@pytest.fixture
def sleeping_nmap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`nmap`, który nic nie skanuje, tylko długo trwa (jak pełny skan portów)."""
    binary = tmp_path / "nmap"
    binary.write_text("#!/bin/sh\nexec sleep 30\n", encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")


def test_effects_disable_the_agent_client_and_revoke_mcp_tokens_by_prefix() -> None:
    keycloak, bao = FakeKeycloak(), FakeBao()
    results = run_effects([_keycloak(keycloak), _openbao(bao)], "kill")
    assert [(r.name, r.ok) for r in results] == [("keycloak", True), ("openbao", True)]
    assert keycloak.enabled is False
    assert bao.revoked_prefixes == ["auth/approle/login"]
    # Token kill switcha żyje tylko na czas odwołania.
    assert bao.requests[-1] == ("POST", "/v1/auth/token/revoke-self")
    assert CERT_GAP in results[1].detail

    restored = run_effects([_keycloak(keycloak)], "restore")
    assert restored[0].ok
    assert keycloak.enabled is True


def test_failed_effect_is_reported_and_does_not_stop_the_others() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    keycloak = KeycloakClientSwitch(
        base_url="http://keycloak:8080/auth",
        realm="sentinel",
        client_id="sentinel-killswitch",
        client_secret="x",
        target_client_id="sentinel-agent",
        client=httpx.Client(transport=httpx.MockTransport(down)),
    )
    bao = FakeBao()
    results = run_effects([keycloak, _openbao(bao)], "kill")
    assert results[0].ok is False
    assert "niedostępny" in results[0].detail
    assert results[1].ok is True


def test_kill_switch_end_to_end_all_three_effects(
    session: Session,
    session_factory: sessionmaker[Session],
    audit_sink: MemoryAudit,
    sleeping_nmap: None,
) -> None:
    guard = ScopeGuard(ScopeConfig.from_dict(SCOPE), audit=audit_sink, resolver=FakeResolver())
    row = create_capability(
        session,
        actor="user:admin",
        tools=["scan_services", "scan_all_ports"],
        targets=["172.30.99.0/24"],
        max_level=2,
    )
    activate_capability(session, row.version, actor="user:admin", reason="test")
    session.commit()
    service = AgentService(session, guard, Planner(None))
    cancellations = Cancellations()
    runtime = ToolRuntime(
        session_factory,
        guard,
        Toolbox(
            nmap=NmapAdapter(SubprocessRunner(cancellations)),
            http=HttpProber(),
            vault=FakeVault(),
        ),
        cancellations=cancellations,
    )

    task = service.create_task("Przeprowadź assessment hosta 172.30.99.10", actor="user:admin")
    service.plan_task(task.id)
    service.approve(task.id, actor="user:admin", reason="ok", step_ids=None, can_approve_level=bool)
    worker = threading.Thread(
        target=service_execute, args=(session_factory, guard, task.id, runtime)
    )
    worker.start()
    deadline = time.monotonic() + 10
    while cancellations.active() == 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert cancellations.active() == 1, "narzędzie powinno właśnie działać"

    keycloak, bao = FakeKeycloak(), FakeBao()
    with session_factory() as admin_session:
        info = AgentService(admin_session, guard, Planner(None)).kill(
            actor="user:admin",
            reason="Test E2E kill switcha",
            effects=[_keycloak(keycloak), _openbao(bao)],
        )
    # 1. Keycloak: klient agenta wyłączony.
    assert keycloak.enabled is False
    # 2. OpenBao: hurtowe odwołanie tokenów serwera MCP.
    assert bao.revoked_prefixes == ["auth/approle/login"]
    assert [e["ok"] for e in info["effects"]] == [True, True]
    # 3. mcp-scanner: strażnik przerywa trwające wywołanie (prawdziwy proces).
    started = time.monotonic()
    assert KillWatcher(session_factory, cancellations).tick() == 1
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert time.monotonic() - started < 5, "proces nmap powinien zginąć od razu, nie po 30 s"

    with session_factory() as check:
        step = check.scalars(select(AgentStep).where(AgentStep.task_id == task.id)).first()
        assert step is not None
        assert (step.status, step.decision) == ("failed", "agent_killed")
        switch = check.get(AgentSwitch, 1)
        assert switch is not None
        assert switch.killed is True
        assert switch.scanner_stopped == 1
        assert switch.scanner_stopped_at is not None
        assert [e["name"] for e in switch.effects or []] == ["keycloak", "openbao"]
        assert check.get(AgentTask, task.id).status == "killed"  # type: ignore[union-attr]
        actions = set(check.scalars(select(AuditLog.action)))
    assert {
        "agent_killed",
        "agent_kill_effects",
        "agent_kill_scanner_stopped",
        "agent_tool_killed",
    } <= actions
    # Drugie sprawdzenie strażnika nie liczy tego samego wyłączenia drugi raz.
    assert KillWatcher(session_factory, cancellations).tick() is None


def service_execute(
    factory: sessionmaker[Session], guard: ScopeGuard, task_id: Any, runtime: ToolRuntime
) -> None:
    with factory() as session:
        AgentService(session, guard, Planner(None)).execute(task_id, LocalGateway(runtime))


def test_restore_only_reenables_identity_while_flag_still_blocks(
    session: Session, audit_sink: MemoryAudit
) -> None:
    guard = ScopeGuard(ScopeConfig.from_dict(SCOPE), audit=audit_sink, resolver=FakeResolver())
    service = AgentService(session, guard, Planner(None))
    effect = FakeEffect("keycloak")
    assert service.restore_identity(actor="user:admin", effects=[effect]) == []
    service.kill(actor="user:admin", reason="stop", effects=[effect])
    restored = service.restore_identity(actor="user:admin", effects=[effect])
    assert restored[0]["ok"] is True
    assert effect.calls == ["kill", "restore"]
    switch = session.get(AgentSwitch, 1)
    assert switch is not None
    assert switch.killed is True  # agent nadal zablokowany do zaliczenia testu


class _Verifier:
    def __init__(self, issued: datetime) -> None:
        self._issued = issued

    def principal(self, token: str) -> Principal:
        return Principal(
            subject="sa",
            username="service-account-sentinel-agent",
            display_name="agent",
            email="",
            kind="agent",
            roles=frozenset({"agent"}),
            permissions=frozenset(),
            mfa=False,
            client_id="sentinel-agent",
            session_id=None,
        )

    def claims(self, token: str) -> dict[str, Any]:
        return {"iat": int(self._issued.timestamp()), "exp": int(time.time()) + 300}


def test_mcp_rejects_tokens_issued_before_the_last_kill() -> None:
    now = datetime.now(UTC)
    killed_at = now - timedelta(minutes=1)
    old = AgentTokenVerifier(
        _Verifier(now - timedelta(minutes=2)),  # type: ignore[arg-type]
        "sentinel-agent",
        state=lambda: (False, killed_at),
    )
    fresh = AgentTokenVerifier(
        _Verifier(now),  # type: ignore[arg-type]
        "sentinel-agent",
        state=lambda: (False, killed_at),
    )
    during = AgentTokenVerifier(
        _Verifier(now),  # type: ignore[arg-type]
        "sentinel-agent",
        state=lambda: (True, killed_at),
    )
    assert anyio.run(old.verify_token, "t") is None
    assert anyio.run(fresh.verify_token, "t") is not None
    assert anyio.run(during.verify_token, "t") is None
