"""Lekkie sprawdzenie strony WWW (L1): jedno zapytanie GET, nagłówek Server i tytuł strony.

Treść pochodzi od badanego hosta, więc jest **niezaufana**: może zawierać instrukcje dla
agenta (zatruty host w demo-lab). Adapter zwraca ją tylko jako dane, skróconą i oznaczoną.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

import httpx

from app.core.scope_guard import ScopedTarget
from app.scanners.runner import ToolError

MAX_BODY = 65_536
MAX_FIELD = 200
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class HttpProbe:
    status: int
    server: str
    title: str
    port: int
    scheme: str


def _clip(value: str) -> str:
    text = " ".join(html.unescape(value).split())
    return text[:MAX_FIELD]


def parse_page(
    status: int, headers: dict[str, str], body: str, *, port: int, scheme: str
) -> HttpProbe:
    match = _TITLE_RE.search(body[:MAX_BODY])
    return HttpProbe(
        status=status,
        server=_clip(headers.get("server", "")),
        title=_clip(match.group(1)) if match else "",
        port=port,
        scheme=scheme,
    )


class HttpProber:
    def __init__(self, client: httpx.Client | None = None) -> None:
        # Bez proxy (cel jest w sieci lokalnej), bez przekierowań, krótki limit czasu. Hosty
        # w sieci wewnętrznej często mają certyfikat self-signed; czytamy tylko nagłówek i tytuł,
        # niczego nie wysyłamy, więc brak weryfikacji TLS nie naraża poświadczeń.
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            trust_env=False,
            verify=False,  # noqa: S501
        )

    def probe(self, target: ScopedTarget, *, port: int = 80, scheme: str = "http") -> HttpProbe:
        if not isinstance(target, ScopedTarget):
            raise TypeError("probe_http przyjmuje wyłącznie ScopedTarget")
        if scheme not in {"http", "https"} or not 1 <= port <= 65535:
            raise ToolError("probe_http: nieprawidłowy schemat albo port")
        host = f"[{target.address}]" if ":" in target.address else target.address
        url = f"{scheme}://{host}:{port}/"
        try:
            with self._client.stream("GET", url, headers={"User-Agent": "sentinel-asi"}) as resp:
                chunks: list[bytes] = []
                size = 0
                for chunk in resp.iter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY:
                        break
                body = b"".join(chunks)[:MAX_BODY].decode(resp.encoding or "utf-8", "replace")
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return parse_page(resp.status_code, headers, body, port=port, scheme=scheme)
        except httpx.HTTPError as error:
            raise ToolError(f"probe_http: {error.__class__.__name__}") from error
