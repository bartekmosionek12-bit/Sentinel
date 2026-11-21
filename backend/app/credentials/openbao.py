"""Klient OpenBao: krótkotrwały token per zadanie i podpis certyfikatu SSH na 15 minut.

Przepływ (ARCHITECTURE §6): logowanie AppRole → token z TTL 15 min i polityką tylko do
podpisu → podpis klucza publicznego wygenerowanego w pamięci → po zadaniu odwołanie tokenu.
Certyfikat SSH wygasa sam po TTL; KRL na hostach jest w ROADMAP.

Wszystko, co zwraca ten moduł poza `SignedCertificate.certificate`, nadaje się do audytu.
Certyfikat z kluczem prywatnym żyje tylko w pamięci `mcp-scanner` na czas jednego wywołania.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

import httpx

from app.explainer.providers import is_local_url

SSH_TTL = timedelta(minutes=15)


class VaultError(Exception):
    """OpenBao jest niedostępny albo odmówił."""


@dataclass(frozen=True)
class SignedCertificate:
    serial: str
    principal: str
    expires_at: datetime
    token_accessor: str
    # Certyfikat (publiczny) do połączenia; nie trafia do bazy, logów ani odpowiedzi API.
    certificate: str = field(repr=False)


class Vault(Protocol):
    def sign_ssh_key(self, public_key: str, *, principal: str) -> SignedCertificate: ...

    def revoke(self, certificate: SignedCertificate) -> None: ...


class OpenBao:
    def __init__(
        self,
        *,
        url: str,
        role_id: str,
        secret_id: str,
        mount: str = "ssh-client-signer",
        role: str = "sentinel-scanner",
        client: httpx.Client | None = None,
    ) -> None:
        if not is_local_url(url):
            raise VaultError("OPENBAO_URL musi wskazywać usługę w sieci lokalnej")
        self._url = url.rstrip("/")
        self._role_id = role_id
        self._secret_id = secret_id
        self._mount = mount
        self._role = role
        self._client = client or httpx.Client(timeout=10.0, trust_env=False)

    def _post(
        self, path: str, body: dict[str, object], token: str | None = None
    ) -> dict[str, object]:
        headers = {"X-Vault-Token": token} if token else {}
        try:
            response = self._client.post(f"{self._url}/v1/{path}", json=body, headers=headers)
        except httpx.HTTPError as error:
            raise VaultError(f"OpenBao: błąd połączenia ({error.__class__.__name__})") from error
        if response.status_code >= 300:
            raise VaultError(f"OpenBao: odpowiedź HTTP {response.status_code} dla {path}")
        return dict(response.json() or {}) if response.content else {}

    def _login(self) -> tuple[str, str]:
        data = self._post(
            "auth/approle/login", {"role_id": self._role_id, "secret_id": self._secret_id}
        )
        auth = dict(data.get("auth") or {})  # type: ignore[call-overload]
        token, accessor = str(auth.get("client_token", "")), str(auth.get("accessor", ""))
        if not token:
            raise VaultError("OpenBao: logowanie AppRole bez tokenu")
        return token, accessor

    def sign_ssh_key(self, public_key: str, *, principal: str) -> SignedCertificate:
        token, accessor = self._login()
        try:
            data = self._post(
                f"{self._mount}/sign/{self._role}",
                {
                    "public_key": public_key,
                    "valid_principals": principal,
                    "ttl": f"{int(SSH_TTL.total_seconds())}s",
                    "cert_type": "user",
                },
                token,
            )
        except VaultError:
            self._revoke_token(token)
            raise
        payload = dict(data.get("data") or {})  # type: ignore[call-overload]
        signed = str(payload.get("signed_key", ""))
        if not signed:
            self._revoke_token(token)
            raise VaultError("OpenBao: brak podpisanego certyfikatu")
        cert = SignedCertificate(
            serial=str(payload.get("serial_number", "")),
            principal=principal,
            expires_at=datetime.now(UTC) + SSH_TTL,
            token_accessor=accessor,
            certificate=signed,
        )
        object.__setattr__(cert, "_token", token)
        return cert

    def _revoke_token(self, token: str) -> None:
        self._post("auth/token/revoke-self", {}, token)

    def revoke(self, certificate: SignedCertificate) -> None:
        token = getattr(certificate, "_token", None)
        if token:
            self._revoke_token(str(token))
            object.__setattr__(certificate, "_token", None)


class FakeVault:
    """Atrapa OpenBao do testów i trybu dry-run: zamiast certyfikatu zwraca kanarek."""

    def __init__(self, certificate: str = "fake-certificate") -> None:
        self._certificate = certificate
        self.issued: list[SignedCertificate] = []
        self.revoked: list[str] = []
        self._counter = 0

    def sign_ssh_key(self, public_key: str, *, principal: str) -> SignedCertificate:
        self._counter += 1
        cert = SignedCertificate(
            serial=f"fake-{self._counter}",
            principal=principal,
            expires_at=datetime.now(UTC) + SSH_TTL,
            token_accessor=f"accessor-{self._counter}",
            certificate=self._certificate,
        )
        self.issued.append(cert)
        return cert

    def revoke(self, certificate: SignedCertificate) -> None:
        self.revoked.append(certificate.serial)
