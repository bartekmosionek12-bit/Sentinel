"""Klucze publiczne realmu Keycloak (JWKS) z pamięcią podręczną.

Jedyne miejsce modułu `iam`, które sięga do sieci: pobiera klucze z wewnętrznego adresu
Keycloaka (sieć `iam`). Odświeża je, gdy token wskazuje nieznany `kid` (rotacja kluczy),
ale nie częściej niż co `min_refresh_seconds`, żeby fałszywy `kid` nie zalewał Keycloaka.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import jwt
from jwt import PyJWK

from app.iam.tokens import TokenError


class JwksKeyProvider:
    def __init__(
        self,
        url: str,
        *,
        timeout: float = 5.0,
        ttl_seconds: float = 3600.0,
        min_refresh_seconds: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = url
        self._ttl = ttl_seconds
        self._min_refresh = min_refresh_seconds
        self._client = client or httpx.Client(timeout=timeout, trust_env=False)
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        try:
            response = self._client.get(self._url)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise TokenError(f"Nie udało się pobrać kluczy JWKS: {error}") from error
        keys: dict[str, Any] = {}
        for item in body.get("keys", []):
            if item.get("use", "sig") != "sig" or item.get("kty") != "RSA":
                continue
            keys[str(item.get("kid"))] = PyJWK(item).key
        self._keys = keys
        self._fetched_at = time.monotonic()

    def key_for(self, token: str) -> Any:
        try:
            kid = str(jwt.get_unverified_header(token).get("kid"))
        except jwt.PyJWTError as error:
            raise TokenError(str(error)) from error
        with self._lock:
            age = time.monotonic() - self._fetched_at
            stale = age > self._ttl
            unknown = kid not in self._keys and age > self._min_refresh
            if not self._keys or stale or unknown:
                self._refresh()
            key = self._keys.get(kid)
        if key is None:
            raise TokenError("Token podpisany nieznanym kluczem")
        return key
