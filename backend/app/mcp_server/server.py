"""Usługa `mcp-scanner`: serwer MCP (Streamable HTTP) nad `ToolRuntime`.

- Uwierzytelnienie: token Bearer z Keycloaka, wyłącznie konto usługowe `sentinel-agent`.
- `tools/list` zwraca tylko narzędzia z aktywnych zdolności agenta (pusta lista po kill switchu).
- `tools/call` przyjmuje identyfikator kroku, cel i parametry; decyzję podejmuje `ToolRuntime`.

Uruchomienie: `python -m app.mcp_server.server` (port 8001, sieć `mcp`, bez portu na hoście).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import anyio
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import Tool as MCPTool

from app.agent.catalog import CATALOG
from app.agent.switch import is_killed
from app.core.db import get_sessionmaker
from app.iam.tokens import TokenError, TokenVerifier
from app.mcp_server.runtime import ToolRequest, ToolRuntime, active_capability

logger = logging.getLogger("sentinel.mcp")
AGENT_SCOPE = "agent"


class AgentTokenVerifier:
    """Akceptuje wyłącznie ważny token konta usługowego agenta."""

    def __init__(self, verifier: TokenVerifier, client_id: str) -> None:
        self._verifier = verifier
        self._client_id = client_id

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            principal = self._verifier.principal(token)
            claims = self._verifier.claims(token)
        except TokenError:
            return None
        if principal.kind != "agent" or principal.client_id != self._client_id:
            return None
        return AccessToken(
            token=token,
            client_id=principal.client_id,
            scopes=[AGENT_SCOPE],
            expires_at=int(claims["exp"]),
            subject=principal.subject,
        )


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
    server = build_server(
        runtime,
        token_verifier=AgentTokenVerifier(get_token_verifier(), settings.agent_client_id),
        issuer_url=settings.oidc_issuer,
        resource_url=settings.mcp_url,
    )
    server.run(transport="streamable-http")


if __name__ == "__main__":  # pragma: no cover
    main()
