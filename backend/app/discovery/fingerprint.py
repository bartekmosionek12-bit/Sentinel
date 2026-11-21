"""Fingerprinting HTTP/HTTPS (L1, tylko GET): tytuł, kod, nagłówki, ciasteczka, TLS,
przekierowania, hash favicony, technologie, oraz flagi (panel, staging, ciekawe nagłówki).

Treść pochodzi od badanego hosta, więc jest niezaufana: zapisujemy ją skróconą, jako dane.
Każda flaga ma listę niezależnych dowodów, a pewność to ich liczba (1 niska, 2 średnia,
3+ wysoka). Reguły są tu jawne i deterministyczne; model językowy w tym nie uczestniczy.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
import socket
import ssl
import struct
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from app.core.scope_guard import ScopedTarget

MAX_BODY = 131_072
MAX_REDIRECTS = 5
WEB_PORTS = {80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200}
TLS_PORTS = {443, 8443}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ICON_RE = re.compile(r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.IGNORECASE)
_HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.IGNORECASE)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", re.IGNORECASE
)

# Technologie: (nazwa, gdzie szukać, wzorzec). Zestaw jak w lekkim Wappalyzerze.
TECH_RULES: tuple[tuple[str, str, str], ...] = (
    ("Apache", "header:server", r"apache"),
    ("nginx", "header:server", r"nginx"),
    ("Microsoft IIS", "header:server", r"microsoft-iis"),
    ("Express", "header:x-powered-by", r"express"),
    ("PHP", "header:x-powered-by", r"php"),
    ("ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("PHP", "cookie", r"^phpsessid$"),
    ("Java", "cookie", r"^jsessionid$"),
    ("ASP.NET", "cookie", r"^asp\.net_sessionid$"),
    ("Laravel", "cookie", r"^laravel_session$"),
    ("Django", "cookie", r"^csrftoken$"),
    ("WordPress", "body", r"wp-content|wp-includes"),
    ("WordPress", "generator", r"wordpress"),
    ("Joomla", "generator", r"joomla"),
    ("Drupal", "header:x-generator", r"drupal"),
    ("Drupal", "generator", r"drupal"),
    ("Angular", "body", r"ng-version=|<app-root"),
    ("React", "body", r"data-reactroot|__next_data__|react-dom"),
    ("Vue.js", "body", r"data-v-[0-9a-f]{6,}|vue\.(?:min\.)?js"),
    ("jQuery", "body", r"jquery[.-][0-9.]*(?:min\.)?js"),
    ("Bootstrap", "body", r"bootstrap(?:\.min)?\.(?:css|js)"),
    ("Grafana", "title", r"grafana"),
    ("Jenkins", "header:x-jenkins", r"."),
    ("Kibana", "header:kbn-name", r"."),
    ("Elasticsearch", "body", r"\"cluster_name\""),
    ("phpMyAdmin", "title", r"phpmyadmin"),
    ("DVWA", "title", r"damn vulnerable"),
    ("OWASP Juice Shop", "title", r"juice shop"),
)

PANEL_TITLE = re.compile(
    r"\b(admin|administra|login|log in|sign in|zaloguj|panel|dashboard|console|konsola|"
    r"phpmyadmin|webmin|cpanel|router)\b",
    re.IGNORECASE,
)
STAGING_NAME = re.compile(
    r"(^|[.-])(staging|stage|stg|test|testing|dev|uat|qa|preprod|demo)([.-]|$|\d)", re.I
)
STAGING_TITLE = re.compile(r"\b(staging|test|testowy|testowa|development|dev|uat|preprod)\b", re.I)
INTERESTING_HEADERS = {
    "x-powered-by": "ujawnia technologię i wersję",
    "server": "ujawnia serwer (z wersją)",
    "x-aspnet-version": "ujawnia wersję ASP.NET",
    "x-debug-token": "tryb debugowania (Symfony)",
    "x-debug": "tryb debugowania",
    "x-backend-server": "ujawnia serwer zaplecza",
    "x-jenkins": "Jenkins",
    "access-control-allow-origin": "CORS",
}
INTERESTING_COOKIES = re.compile(r"(debug|admin|test|staging|role|is_admin)", re.IGNORECASE)
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options")


@dataclass
class HttpResult:
    url: str
    port: int
    scheme: str
    status: int | None = None
    title: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    redirects: list[str] = field(default_factory=list)
    tls: dict[str, Any] | None = None
    favicon_hash: int | None = None
    technologies: list[str] = field(default_factory=list)
    paths: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _clip(value: str, size: int = 200) -> str:
    return " ".join(html.unescape(value).split())[:size]


def mmh3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 (ze znakiem), jak hash favicony w Shodan."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h = seed & 0xFFFFFFFF
    rounded = length - length % 4
    for i in range(0, rounded, 4):
        (k,) = struct.unpack_from("<I", data, i)
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    k = 0
    tail = data[rounded:]
    if len(tail) == 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash(content: bytes) -> int:
    return mmh3_32(base64.encodebytes(content))


def detect_technologies(
    headers: dict[str, str], cookies: list[str], body: str, title: str
) -> list[str]:
    generator = _GENERATOR_RE.search(body)
    sources = {
        "body": body[:MAX_BODY].lower(),
        "title": title.lower(),
        "generator": (generator.group(1) if generator else "").lower(),
    }
    found: list[str] = []
    for name, where, pattern in TECH_RULES:
        if where.startswith("header:"):
            values = [headers.get(where[7:], "")]
        elif where == "cookie":
            values = [c.lower() for c in cookies]
        else:
            values = [sources[where]]
        if any(v and re.search(pattern, v, re.IGNORECASE) for v in values) and name not in found:
            found.append(name)
    return found


def tls_info(address: str, port: int, server_name: str | None) -> dict[str, Any] | None:
    """Certyfikat bez weryfikacji (sieć wewnętrzna, self-signed): podmiot, wystawca, daty, SAN."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((address, port), timeout=4) as raw,
            context.wrap_socket(raw, server_hostname=server_name or None) as sock,
        ):
            der = sock.getpeercert(binary_form=True)
            version = sock.version()
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = [str(n.value) for n in san.value]
        except x509.ExtensionNotFound:
            names = []
        return {
            "subject": cert.subject.rfc4514_string()[:200],
            "issuer": cert.issuer.rfc4514_string()[:200],
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "san": names[:20],
            "self_signed": cert.subject == cert.issuer,
            "sha256": hashlib.sha256(der).hexdigest(),
            "version": version,
        }
    except Exception:
        return {"sha256": hashlib.sha256(der).hexdigest(), "version": version}


class HttpFingerprinter:
    """Tylko GET (i HEAD nie jest potrzebny): nic nie wysyłamy, nie logujemy się, nie zgadujemy."""

    def __init__(self, paths: list[str] | None = None, timeout: float = 6.0) -> None:
        self._paths = paths or []
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
            verify=False,  # noqa: S501 - sieć wewnętrzna, tylko odczyt
            headers={"User-Agent": "sentinel-asi/discovery"},
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, url: str) -> tuple[httpx.Response, bytes]:
        with self._client.stream("GET", url) as response:
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY:
                    break
            return response, b"".join(chunks)[:MAX_BODY]

    def probe(self, target: ScopedTarget, port: int, scheme: str) -> HttpResult:
        if not isinstance(target, ScopedTarget):
            raise TypeError("fingerprint przyjmuje wyłącznie ScopedTarget")
        host = f"[{target.address}]" if ":" in target.address else target.address
        base = f"{scheme}://{host}:{port}"
        result = HttpResult(url=f"{base}/", port=port, scheme=scheme)
        url = result.url
        try:
            # Przekierowania śledzimy sami i tylko w obrębie tego samego hosta i portu.
            for _ in range(MAX_REDIRECTS + 1):
                response, body = self._get(url)
                location = response.headers.get("location")
                if response.is_redirect and location:
                    nxt = str(response.url.join(location))
                    result.redirects.append(nxt[:300])
                    if not nxt.startswith(base):
                        break
                    url = nxt
                    continue
                break
        except httpx.HTTPError as error:
            result.error = error.__class__.__name__
            return result
        text = body.decode(response.encoding or "utf-8", "replace")
        headers = {k.lower(): _clip(v, 300) for k, v in response.headers.items()}
        match = _TITLE_RE.search(text)
        result.status = response.status_code
        result.title = _clip(match.group(1)) if match else ""
        result.headers = headers
        result.cookies = [
            {
                "name": _clip(c.split("=", 1)[0], 80),
                "secure": "secure" in c.lower(),
                "httponly": "httponly" in c.lower(),
            }
            for c in response.headers.get_list("set-cookie")
        ]
        result.technologies = detect_technologies(
            headers, [c["name"] for c in result.cookies], text, result.title
        )
        icon = _ICON_RE.search(text)
        href = _HREF_RE.search(icon.group(0)) if icon else None
        icon_url = str(response.url.join(href.group(1))) if href else f"{base}/favicon.ico"
        if icon_url.startswith(base):
            try:
                icon_response, icon_body = self._get(icon_url)
                if icon_response.status_code == 200 and icon_body:
                    result.favicon_hash = favicon_hash(icon_body)
            except httpx.HTTPError:
                pass
        for path in self._paths:
            try:
                path_response, _ = self._get(f"{base}{path}")
                result.paths[path] = path_response.status_code
            except httpx.HTTPError:
                continue
        if scheme == "https":
            result.tls = tls_info(target.address, port, target.hostname)
        return result


def flags_for(hostname: str | None, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flagi z dowodami. Pewność = liczba niezależnych dowodów."""
    panel: list[str] = []
    staging: list[str] = []
    headers_found: list[str] = []
    cookies_found: list[str] = []
    missing_security: list[str] = []
    if hostname and STAGING_NAME.search(hostname):
        staging.append(f"nazwa hosta: {hostname}")
    for item in results:
        if item.get("error"):
            continue
        where = f":{item['port']}"
        title = item.get("title") or ""
        if PANEL_TITLE.search(title):
            panel.append(f"tytuł{where}: {title[:80]}")
        for path, code in (item.get("paths") or {}).items():
            if code in (200, 401, 403):
                panel.append(f"{path}{where} → {code}")
        if any("login" in r or "admin" in r for r in item.get("redirects") or []):
            panel.append(f"przekierowanie{where} do logowania")
        if STAGING_TITLE.search(title):
            staging.append(f"tytuł{where}: {title[:80]}")
        for name in (item.get("tls") or {}).get("san") or []:
            if STAGING_NAME.search(name):
                staging.append(f"certyfikat{where}: {name}")
        headers = item.get("headers") or {}
        for header, why in INTERESTING_HEADERS.items():
            value = headers.get(header)
            if not value:
                continue
            if header == "server" and not re.search(r"\d", value):
                continue
            if header == "access-control-allow-origin" and value != "*":
                continue
            headers_found.append(f"{header}: {value[:60]}{where} ({why})")
        for cookie in item.get("cookies") or []:
            reasons = []
            if INTERESTING_COOKIES.search(cookie["name"]):
                reasons.append("nazwa")
            if not cookie.get("httponly"):
                reasons.append("bez HttpOnly")
            if item.get("scheme") == "https" and not cookie.get("secure"):
                reasons.append("bez Secure")
            if reasons:
                cookies_found.append(f"{cookie['name']}{where} ({', '.join(reasons)})")
        if item.get("scheme") == "https":
            missing = [h for h in SECURITY_HEADERS if h not in headers]
            if missing:
                missing_security.append(f"{where}: brak {', '.join(missing)}")
    flags = []
    for kind, label, evidence in (
        ("panel", "Panel administracyjny lub logowania", panel),
        ("staging", "Środowisko testowe / staging", staging),
        ("header", "Ciekawe nagłówki", headers_found),
        ("cookie", "Ciekawe ciasteczka", cookies_found),
        ("security_headers", "Brak nagłówków bezpieczeństwa (HTTPS)", missing_security),
    ):
        unique = list(dict.fromkeys(evidence))
        if unique:
            confidence = (
                "wysoka" if len(unique) >= 3 else "średnia" if len(unique) == 2 else "niska"
            )
            flags.append(
                {"kind": kind, "label": label, "evidence": unique[:10], "confidence": confidence}
            )
    return flags


def web_ports(services: list[dict[str, Any]]) -> list[tuple[int, str]]:
    """Porty z usługą WWW: po nazwie usługi z nmap albo po typowym numerze portu."""
    out: list[tuple[int, str]] = []
    for service in services:
        name = (service.get("name") or "").lower()
        port = int(service["port"])
        tunnel_tls = "ssl" in name or "https" in name or port in TLS_PORTS
        if "http" in name or port in WEB_PORTS:
            out.append((port, "https" if tunnel_tls else "http"))
    return out
