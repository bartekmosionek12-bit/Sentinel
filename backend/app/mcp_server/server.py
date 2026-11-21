"""Usługa `mcp-scanner`: serwer MCP (Streamable HTTP) nad `ToolRuntime`.

- Uwierzytelnienie: token Bearer z Keycloaka, wyłącznie konto usługowe `sentinel-agent`.
- `tools/list` zwraca tylko narzędzia z aktywnych zdolności agenta (pusta lista po kill switchu).
- `tools/call` przyjmuje identyfikator kroku, cel i parametry; decyzję podejmuje `ToolRuntime`.

Uruchomienie: `python -m app.mcp_server.server` (port 8001, sieć `mcp`, bez portu na hoście).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import anyio
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import Tool as MCPTool
from sqlalchemy.orm import Session

from app.agent.catalog import CATALOG
from app.agent.switch import is_killed
from app.core.db import get_sessionmaker
from app.iam.tokens import TokenError, TokenVerifier
from app.mcp_server.runtime import ToolRequest, ToolRuntime, active_capability
from app.mcp_server.watcher import KillWatcher
from app.models import AgentSwitch

logger = logging.getLogger("sentinel.mcp")
AGENT_SCOPE = "agent"


def kill_state(session: Session) -> tuple[bool, datetime | None]:
    switch = session.get(AgentSwitch, 1)
    if switch is None:
        return False, None
    return bool(switch.killed), switch.killed_at


class AgentTokenVerifier:
    """Akceptuje wyłącznie ważny token konta usługowego agenta.

    Po kill switchu odrzuca każdy token, a po ponownym włączeniu także tokeny wydane przed
    ostatnim wyłączeniem (`iat` sprzed `killed_at`). Wyłączenie klienta w Keycloak blokuje
    nowe tokeny, a ta reguła stare, które jeszcze nie wygasły (do 5 minut).
    """

    def __init__(
        self,
        verifier: TokenVerifier,
        client_id: str,
        state: Callable[[], tuple[bool, datetime | None]] | None = None,
    ) -> None:
        self._verifier = verifier
        self._client_id = client_id
        self._state = state or _db_kill_state

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            principal = self._verifier.principal(token)
            claims = self._verifier.claims(token)
        except TokenError:
            return None
        if principal.kind != "agent" or principal.client_id != self._client_id:
            return None
        killed, killed_at = await anyio.to_thread.run_sync(self._state)
        issued = datetime.fromtimestamp(int(claims["iat"]), UTC)
        if killed or (killed_at is not None and issued <= _aware(killed_at)):
            logger.warning("agent_token_rejected_after_kill")
            return None
        return AccessToken(
            token=token,
            client_id=principal.client_id,
            scopes=[AGENT_SCOPE],
            expires_at=int(claims["exp"]),
            subject=principal.subject,
        )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _db_kill_state() -> tuple[bool, datetime | None]:
    with get_sessionmaker()() as session:
        return kill_state(session)


class ScannerServer(FastMCP):
    """FastMCP z listą narzędzi przefiltrowaną według aktywnych zdolności agenta."""

    async def list_tools(self) -> list[MCPTool]:
        tools = await super().list_tools()

        def allowed() -> set[str]:
            with get_sessionmaker()() as session:
                if is_killed(session):
                    return set()
                capability = active_capability(session)
                return set(capability.tools) if capability else set()

        names = await anyio.to_thread.run_sync(allowed)
        return [tool for tool in tools if tool.name in names]


def build_server(
    runtime: ToolRuntime,
    *,
    token_verifier: AgentTokenVerifier | None,
    issuer_url: str = "http://keycloak:8080/auth/realms/sentinel",
    resource_url: str = "http://mcp-scanner:8001/mcp",
    host: str = "0.0.0.0",  # noqa: S104 - tylko sieć wewnętrzna `mcp`, bez portu na hoście
    port: int = 8001,
) -> ScannerServer:
    auth = (
        AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=resource_url,
            required_scopes=[AGENT_SCOPE],
        )
        if token_verifier
        else None
    )
    server = ScannerServer(
        "sentinel-mcp-scanner",
        instructions=(
            "Narzędzia skanujące Sentinel ASI. Każde wywołanie musi odpowiadać krokowi "
            "zatwierdzonemu przez człowieka; decyzję podejmuje polityka po stronie serwera."
        ),
        token_verifier=token_verifier,
        auth=auth,
        host=host,
        port=port,
        stateless_http=True,
        json_response=True,
    )

    for spec in CATALOG.values():
        _register(server, runtime, spec.name, spec.description, int(spec.level))
    return server


def _register(
    server: ScannerServer, runtime: ToolRuntime, name: str, description: str, level: int
) -> None:
    async def handler(
        step_id: str, target: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            step = uuid.UUID(step_id)
        except ValueError:
            return {"allowed": False, "code": "unknown_step", "reason": "Nieprawidłowy krok"}
        request = ToolRequest(step_id=step, tool=name, target=target, params=dict(params or {}))
        response = await anyio.to_thread.run_sync(runtime.call, request)
        return response.as_dict()

    server.add_tool(
        handler,
        name=name,
        description=f"[L{level}] {description}",
    )


def main() -> None:  # pragma: no cover - uruchamiane w kontenerze
    from app.core.config import get_settings
    from app.core.logging import configure_logging
    from app.iam.deps import get_token_verifier
    from app.runtime import get_scope_guard, mcp_toolbox

    settings = get_settings()
    configure_logging(settings.log_level)
    runtime = ToolRuntime(get_sessionmaker(), get_scope_guard(), mcp_toolbox(settings))
    # Kill switch: przerywa trwające wywołania (procesy narzędzi, połączenia SSH).
    KillWatcher(get_sessionmaker()).start()
    server = build_server(
        runtime,
        token_verifier=AgentTokenVerifier(get_token_verifier(), settings.agent_client_id),
        issuer_url=settings.oidc_issuer,
        resource_url=settings.mcp_url,
    )
    server.run(transport="streamable-http")


if __name__ == "__main__":  # pragma: no cover
    main()
