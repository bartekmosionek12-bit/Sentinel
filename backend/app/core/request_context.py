"""Kontekst bieżącego żądania: identyfikator żądania i tożsamość wywołującego.

Middleware tworzy kontekst na początku żądania, a `get_principal` uzupełnia go po weryfikacji
tokenu. Dzięki temu każdy wpis audytu zapisany w trakcie żądania (także przez `scope_guard`
i serwisy, które nie znają tokenu) ma `request_id`, `actor_type` i `actor_id`.

Kontekst jest obiektem modyfikowalnym: zależności synchroniczne FastAPI działają w puli
wątków na kopii zmiennych kontekstowych, więc zmiana referencji nie wróciłaby do żądania,
a zmiana pól tego samego obiektu jest widoczna wszędzie.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar
from dataclasses import dataclass

from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_HEADER = "x-request-id"
_VALID_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


@dataclass
class RequestContext:
    request_id: str
    actor_type: str | None = None
    actor_id: str | None = None


_current: ContextVar[RequestContext | None] = ContextVar("sentinel_request", default=None)


def current() -> RequestContext | None:
    return _current.get()


def _incoming_id(scope: Scope) -> str:
    for name, value in scope.get("headers", []):
        if name == REQUEST_ID_HEADER.encode():
            candidate = str(value.decode("latin-1"))
            if _VALID_ID.match(candidate):
                return candidate
    return uuid.uuid4().hex


class RequestContextMiddleware:
    """Nadaje identyfikator żądania (albo przyjmuje poprawny z proxy) i oddaje go w nagłówku."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        context = RequestContext(request_id=_incoming_id(scope))
        scope.setdefault("state", {})["request_id"] = context.request_id
        token = _current.set(context)

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((REQUEST_ID_HEADER.encode(), context.request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        finally:
            _current.reset(token)
