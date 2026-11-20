"""Brama wykonawcy do narzędzi: klient MCP (produkcja) albo runtime w procesie (testy).

Wykonawca agenta nie importuje adapterów skanerów. Jedyna droga do sieci to serwer MCP,
który sam sprawdza krok, zatwierdzenie, zdolności i `scope_guard`.
"""

from __future__ import annotations

import time
from typing import Any, Protocol

import anyio
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from app.mcp_server.runtime import ToolRequest, ToolResponse, ToolRuntime


class ToolGateway(Protocol):
    def call(self, request: ToolRequest) -> ToolResponse: ...


class LocalGateway:
    """Ten sam `ToolRuntime` bez transportu HTTP (testy i uruchomienie jednoprocesowe)."""

    def __init__(self, runtime: ToolRuntime) -> None:
        self._runtime = runtime

    def call(self, request: ToolRequest) -> ToolResponse:
        return self._runtime.call(request)


class ClientCredentials:
    """Token konta usługowego agenta z Keycloaka (client credentials), z pamięcią podręczną."""

    def __init__(self, token_url: str, client_id: str, client_secret: str) -> None:
        self._url = token_url
        self._id = client_id
        self._secret = client_secret
        self._token = ""
        self._expires = 0.0

    def token(self) -> str:
        if self._token and time.monotonic() < self._expires - 30:
            return self._token
        response = httpx.post(
            self._url,
            data={"grant_type": "client_credentials"},
            auth=(self._id, self._secret),
            timeout=10.0,
            trust_env=False,
        )
        response.raise_for_status()
        body = response.json()
        self._token = str(body["access_token"])
        self._expires = time.monotonic() + float(body.get("expires_in", 60))
        return self._token


class McpGateway:
    def __init__(self, url: str, credentials: ClientCredentials, timeout: float = 1800) -> None:
        self._url = url
        self._credentials = credentials
        self._timeout = timeout

    def call(self, request: ToolRequest) -> ToolResponse:
        return anyio.run(self._call, request)

    async def _call(self, request: ToolRequest) -> ToolResponse:
        headers = {"Authorization": f"Bearer {self._credentials.token()}"}
        async with (
            httpx.AsyncClient(headers=headers, timeout=self._timeout, trust_env=False) as http,
            streamable_http_client(self._url, http_client=http) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool(
                request.tool,
                {
                    "step_id": str(request.step_id),
                    "target": request.target,
                    "params": request.params,
                },
            )
        data: dict[str, Any] = dict(result.structuredContent or {})
        if "result" in data and "allowed" not in data:
            data = dict(data["result"])
        if result.isError or "allowed" not in data:
            return ToolResponse(False, "mcp_error", "Serwer MCP zwrócił błąd")
        return ToolResponse(
            bool(data["allowed"]),
            str(data.get("code", "")),
            str(data.get("reason", "")),
            dict(data.get("result") or {}),
        )
