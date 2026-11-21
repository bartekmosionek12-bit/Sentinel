"""Weryfikacja tokenów dostępu OIDC (Keycloak) i budowa tożsamości wywołującego.

Backend ufa wyłącznie podpisowi tokenu (RS256 z kluczy realmu), wydawcy, odbiorcy i
terminowi ważności. Role pochodzą z `realm_access.roles`, a uprawnienia wylicza backend
z `rules/roles.yaml`. Token bez znanej roli nie daje żadnych uprawnień.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

import jwt

from app.iam.rbac import PrincipalKind, RoleCatalog

ALGORITHMS = ["RS256"]


class TokenError(Exception):
    """Token nieważny: podpis, wydawca, odbiorca, termin albo brak wymaganych pól."""


@dataclass(frozen=True)
class Principal:
    """Kto wywołuje API. Tworzony wyłącznie z poprawnie zweryfikowanego tokenu."""

    subject: str
    username: str
    display_name: str
    email: str
    kind: PrincipalKind
    roles: frozenset[str]
    permissions: frozenset[str]
    mfa: bool
    client_id: str
    session_id: str | None

    @property
    def actor(self) -> str:
        """Aktor w dzienniku audytu."""
        prefix = {"human": "user", "agent": "agent", "system": "system"}[self.kind]
        return f"{prefix}:{self.username}"

    def can(self, permission: str) -> bool:
        return permission in self.permissions


class KeyProvider(Protocol):
    def key_for(self, token: str) -> Any:
        """Klucz publiczny do weryfikacji podpisu tokenu."""
        ...


class StaticKeyProvider:
    """Jeden znany klucz publiczny (testy, tryb bez Keycloaka)."""

    def __init__(self, key: Any) -> None:
        self._key = key

    def key_for(self, token: str) -> Any:
        return self._key


@dataclass(frozen=True)
class TokenPolicy:
    issuer: str
    audience: str
    # Wartości `amr`, które oznaczają drugi składnik. Keycloak wpisuje je z konfiguracji
    # kroków przepływu logowania (infra/keycloak: `pwd` dla hasła, `otp` dla TOTP), więc
    # token mówi, czym naprawdę uwierzytelnił się użytkownik, a nie tylko z jakiej aplikacji.
    mfa_methods: frozenset[str] = frozenset({"otp", "hwk", "webauthn"})
    leeway_seconds: int = 10


class TokenVerifier:
    def __init__(
        self, keys: KeyProvider, policy: TokenPolicy, catalog: Callable[[], RoleCatalog]
    ) -> None:
        self._keys = keys
        self._policy = policy
        self._catalog = catalog

    def claims(self, token: str) -> dict[str, Any]:
        try:
            key = self._keys.key_for(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=ALGORITHMS,
                audience=self._policy.audience,
                issuer=self._policy.issuer,
                leeway=self._policy.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except (jwt.PyJWTError, KeyError, ValueError) as error:
            raise TokenError(str(error)) from error
        return claims

    def principal(self, token: str) -> Principal:
        claims = self.claims(token)
        return principal_from_claims(claims, self._policy, self._catalog())


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, list):
        return (str(v) for v in value)
    if isinstance(value, str):
        return (value,)
    return ()


def principal_from_claims(
    claims: dict[str, Any], policy: TokenPolicy, catalog: RoleCatalog
) -> Principal:
    realm_access = claims.get("realm_access") or {}
    roles = frozenset(_strings(realm_access.get("roles") if isinstance(realm_access, dict) else []))
    client_id = str(claims.get("azp") or claims.get("client_id") or "")
    amr = frozenset(_strings(claims.get("amr")))
    mfa = bool(amr & policy.mfa_methods)
    kind = catalog.kind_of(roles)
    username = str(claims.get("preferred_username") or claims.get("client_id") or claims["sub"])
    if kind != "human":
        # Konta usług nie logują się interaktywnie; MFA ich nie dotyczy, a uprawnienia
        # nadaje wyłącznie rola (dla agenta: zdolności w Etapie 5).
        mfa = False
    return Principal(
        subject=str(claims["sub"]),
        username=username,
        display_name=str(claims.get("name") or username),
        email=str(claims.get("email") or ""),
        kind=kind,
        roles=roles,
        permissions=catalog.resolve(roles, mfa=mfa),
        mfa=mfa,
        client_id=client_id,
        session_id=str(claims["sid"]) if claims.get("sid") else None,
    )
