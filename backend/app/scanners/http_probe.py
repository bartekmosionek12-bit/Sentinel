"""Lekkie sprawdzenie strony WWW (L1): jedno zapytanie GET, nagłówek Server i tytuł strony.

Treść pochodzi od badanego hosta, więc jest **niezaufana**: może zawierać instrukcje dla
agenta (zatruty host w demo-lab). Adapter zwraca ją tylko jako dane, skróconą i oznaczoną.
"""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography import x509

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
    headers: dict[str, str] | None = None
    cookies: list[str] | None = None
    tls_sha256: str | None = None
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_expires_at: str | None = None
    redirects_to: str | None = None
    favicon_sha256: str | None = None
    admin_paths: list[str] | None = None
    technologies: list[str] | None = None
    flags: list[dict[str, Any]] | None = None


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
                base = parse_page(resp.status_code, headers, body, port=port, scheme=scheme)
                cookies = [
                    part.split("=", 1)[0].strip()[:80]
                    for part in resp.headers.get_list("set-cookie")
                ]
                stream = resp.extensions.get("network_stream")
                tls_sha256 = None
                tls_subject = None
                tls_issuer = None
                tls_expires_at = None
                if scheme == "https" and stream is not None:
                    ssl_object = stream.get_extra_info("ssl_object")
                    if ssl_object is not None:
                        cert = ssl_object.getpeercert(binary_form=True)
                        if cert:
                            tls_sha256 = hashlib.sha256(cert).hexdigest()
                            parsed = x509.load_der_x509_certificate(cert)
                            tls_subject = parsed.subject.rfc4514_string()[:MAX_FIELD]
                            tls_issuer = parsed.issuer.rfc4514_string()[:MAX_FIELD]
                            tls_expires_at = parsed.not_valid_after_utc.isoformat()
            admin_paths = []
            for path in ("/admin", "/login"):
                try:
                    response = self._client.head(
                        url.rstrip("/") + path, headers={"User-Agent": "sentinel-asi"}
                    )
                    if response.status_code in (200, 301, 302, 303, 307, 308, 401, 403):
                        admin_paths.append(path)
                except httpx.HTTPError:
                    pass
            favicon_sha256 = None
            try:
                with self._client.stream("GET", url.rstrip("/") + "/favicon.ico") as icon:
                    if icon.status_code == 200:
                        data = b"".join(icon.iter_bytes())[:MAX_BODY]
                        favicon_sha256 = hashlib.sha256(data).hexdigest() if data else None
            except httpx.HTTPError:
                pass
            flags = []
            evidence = []
            if admin_paths:
                evidence.append("ścieżki " + ", ".join(admin_paths))
                flags.append(
                    {"kind": "admin_panel", "evidence": evidence, "confidence": len(evidence)}
                )
            staging_evidence = []
            if target.hostname and re.search(
                r"(^|[.-])(stage|staging|test|dev)([.-]|$)", target.hostname, re.I
            ):
                staging_evidence.append("nazwa hosta")
            if re.search(r"\b(stage|staging|test|dev)\b", base.title, re.I):
                staging_evidence.append("tytuł strony")
            if staging_evidence:
                flags.append(
                    {
                        "kind": "staging",
                        "evidence": staging_evidence,
                        "confidence": len(staging_evidence),
                    }
                )
            header_evidence = [
                name for name in ("server", "x-powered-by", "x-aspnet-version") if headers.get(name)
            ]
            if header_evidence:
                flags.append(
                    {
                        "kind": "interesting_headers",
                        "evidence": header_evidence,
                        "confidence": len(header_evidence),
                    }
                )
            cookie_evidence = [
                name for name in cookies if re.search(r"session|auth|token|admin", name, re.I)
            ]
            if cookie_evidence:
                flags.append(
                    {
                        "kind": "interesting_cookies",
                        "evidence": cookie_evidence,
                        "confidence": len(cookie_evidence),
                    }
                )
            return HttpProbe(
                status=base.status,
                server=base.server,
                title=base.title,
                port=port,
                scheme=scheme,
                headers={
                    k: _clip(v)
                    for k, v in headers.items()
                    if k not in {"set-cookie", "www-authenticate"}
                },
                cookies=cookies,
                tls_sha256=tls_sha256,
                tls_subject=tls_subject,
                tls_issuer=tls_issuer,
                tls_expires_at=tls_expires_at,
                redirects_to=headers.get("location"),
                favicon_sha256=favicon_sha256,
                admin_paths=admin_paths,
                technologies=[],
                flags=flags,
            )
        except httpx.HTTPError as error:
            raise ToolError(f"probe_http: {error.__class__.__name__}") from error
