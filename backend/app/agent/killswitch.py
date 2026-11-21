"""Skutki kill switcha poza bazą: tożsamość agenta (Keycloak) i jego poświadczenia (OpenBao).

Kolejność w `AgentService.kill` (ARCHITECTURE §5.2):

1. flaga w bazie (natychmiast: MCP, walidator i wykonawca odrzucają każde kolejne wywołanie),
2. `KeycloakClientSwitch`: klient `sentinel-agent` wyłączony przez admin API, więc Keycloak nie
   wyda nowego tokenu; tokeny wydane przed wyłączeniem odrzuca `mcp-scanner` (data `iat`),
3. `OpenBaoLeaseRevoker`: `sys/leases/revoke-prefix` dla logowań AppRole serwera MCP, czyli
   hurtowe odwołanie wszystkich tokenów, którymi `mcp-scanner` mógłby podpisać certyfikat,
4. `mcp-scanner` sam zatrzymuje trwające wywołania (`app.mcp_server.watcher`).

Luka nazwana wprost: certyfikat SSH podpisany przed kill switchem działa do końca swojego TTL
(najwyżej 15 minut), bo hosty nie mają listy KRL (ROADMAP). Odwołanie tokenu OpenBao nie
unieważnia już wydanego certyfikatu.

Każdy skutek działa niezależnie: błąd Keycloaka nie zatrzymuje odwołania w OpenBao, a wynik
każdego kroku trafia do bazy, audytu i konsoli.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx

from app.explainer.providers import is_local_url

CERT_GAP = (
    "Certyfikaty SSH wydane przed wyłączeniem działają do końca TTL (najwyżej 15 minut), "
    "bo hosty nie mają listy odwołań KRL."
)


class KillEffectError(Exception):
    """Skutek kill switcha się nie powiódł (opis bez sekretów)."""


@dataclass(frozen=True)
class EffectResult:
    name: str
    ok: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


class KillEffect(Protocol):
    name: str

    def kill(self) -> str: ...

    def restore(self) -> str: ...


def run_effects(effects: Sequence[KillEffect], action: str) -> list[EffectResult]:
    """Wykonuje `kill` albo `restore` na każdym skutku; błąd jednego nie zatrzymuje innych."""
    results: list[EffectResult] = []
    for effect in effects:
        try:
            detail = effect.kill() if action == "kill" else effect.restore()
            results.append(EffectResult(effect.name, True, detail))
        except KillEffectError as error:
            results.append(EffectResult(effect.name, False, str(error)[:300]))
        except Exception as error:
            results.append(
                EffectResult(effect.name, False, f"Nieoczekiwany błąd: {error.__class__.__name__}")
            )
    return results


def _client(client: httpx.Client | None) -> httpx.Client:
    return client or httpx.Client(timeout=10.0, trust_env=False)


class KeycloakClientSwitch:
    """Wyłącza i włącza klienta agenta przez admin API Keycloaka.

    Konto usługowe `sentinel-killswitch` ma w realmie wyłącznie role `view-clients` i
    `manage-clients` z `realm-management`; nie zarządza użytkownikami ani realmem.
    """

    name = "keycloak"

    def __init__(
        self,
        *,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        target_client_id: str,
        client: httpx.Client | None = None,
    ) -> None:
        if not is_local_url(base_url):
            raise KillEffectError("Adres Keycloaka musi wskazywać usługę w sieci lokalnej")
        self._base = base_url.rstrip("/")
        self._realm = realm
        self._id = client_id
        self._secret = client_secret
        self._target = target_client_id
        self._http = _client(client)

    def _token(self) -> str:
        try:
            response = self._http.post(
                f"{self._base}/realms/{self._realm}/protocol/openid-connect/token",
                data={"grant_type": "client_credentials"},
                auth=(self._id, self._secret),
            )
        except httpx.HTTPError as error:
            raise KillEffectError(f"Keycloak niedostępny ({error.__class__.__name__})") from error
        if response.status_code != 200:
            raise KillEffectError(
                f"Keycloak odmówił tokenu kill switcha (HTTP {response.status_code})"
            )
        return str(response.json()["access_token"])

    def _set_enabled(self, enabled: bool) -> str:
        headers = {"Authorization": f"Bearer {self._token()}"}
        clients = f"{self._base}/admin/realms/{self._realm}/clients"
        try:
            found = self._http.get(clients, params={"clientId": self._target}, headers=headers)
            if found.status_code != 200 or not found.json():
                raise KillEffectError(
                    f"Nie znaleziono klienta {self._target} (HTTP {found.status_code})"
                )
            representation = dict(found.json()[0])
            representation["enabled"] = enabled
            updated = self._http.put(
                f"{clients}/{representation['id']}", json=representation, headers=headers
            )
        except httpx.HTTPError as error:
            raise KillEffectError(f"Keycloak niedostępny ({error.__class__.__name__})") from error
        if updated.status_code not in (200, 204):
            raise KillEffectError(f"Keycloak odrzucił zmianę klienta (HTTP {updated.status_code})")
        state = "włączony" if enabled else "wyłączony"
        return f"Klient {self._target} {state}"

    def kill(self) -> str:
        return self._set_enabled(False) + "; Keycloak nie wyda nowego tokenu agenta"

    def restore(self) -> str:
        return self._set_enabled(True)


class OpenBaoLeaseRevoker:
    """Hurtowe odwołanie tokenów `mcp-scanner` w OpenBao (`sys/leases/revoke-prefix`).

    Loguje się własnym AppRole (osobny punkt montowania `killswitch`), którego polityka
    pozwala wyłącznie na odwołanie leasów pod prefiksem logowań AppRole serwera MCP. Dzięki
    osobnemu punktowi montowania odwołanie nie dotyka tokenu samego kill switcha.
    """

    name = "openbao"
    prefix = "auth/approle/login"

    def __init__(
        self,
        *,
        url: str,
        role_id: str,
        secret_id: str,
        mount: str = "killswitch",
        client: httpx.Client | None = None,
    ) -> None:
        if not is_local_url(url):
            raise KillEffectError("OPENBAO_URL musi wskazywać usługę w sieci lokalnej")
        self._url = url.rstrip("/")
        self._role_id = role_id
        self._secret_id = secret_id
        self._mount = mount
        self._http = _client(client)

    @classmethod
    def from_file(cls, url: str, path: Path, **kwargs: Any) -> OpenBaoLeaseRevoker:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            url=url, role_id=str(data["role_id"]), secret_id=str(data["secret_id"]), **kwargs
        )

    def _call(
        self, method: str, path: str, body: dict[str, Any], token: str | None
    ) -> httpx.Response:
        headers = {"X-Vault-Token": token} if token else {}
        try:
            return self._http.request(method, f"{self._url}/v1/{path}", json=body, headers=headers)
        except httpx.HTTPError as error:
            raise KillEffectError(f"OpenBao niedostępny ({error.__class__.__name__})") from error

    def kill(self) -> str:
        login = self._call(
            "POST",
            f"auth/{self._mount}/login",
            {"role_id": self._role_id, "secret_id": self._secret_id},
            None,
        )
        if login.status_code != 200:
            raise KillEffectError(
                f"OpenBao odmówił logowania kill switcha (HTTP {login.status_code})"
            )
        token = str(login.json()["auth"]["client_token"])
        try:
            revoked = self._call("PUT", f"sys/leases/revoke-prefix/{self.prefix}", {}, token)
            if revoked.status_code not in (200, 204):
                raise KillEffectError(
                    f"OpenBao odrzucił revoke-prefix (HTTP {revoked.status_code})"
                )
        finally:
            self._call("POST", "auth/token/revoke-self", {}, token)
        return f"Odwołano wszystkie tokeny pod {self.prefix}. {CERT_GAP}"

    def restore(self) -> str:
        return "Nic do przywrócenia: mcp-scanner zaloguje się ponownie przy następnym kroku"


class FakeEffect:
    """Atrapa do testów i instalacji bez Keycloaka lub OpenBao."""

    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name = name
        self._fail = fail
        self.calls: list[str] = []

    def kill(self) -> str:
        self.calls.append("kill")
        if self._fail:
            raise KillEffectError(f"{self.name}: atrapa błędu")
        return f"{self.name}: wyłączono"

    def restore(self) -> str:
        self.calls.append("restore")
        return f"{self.name}: przywrócono"


class NotConfigured:
    """Skutek, którego nie da się wykonać, bo brakuje konfiguracji (widoczne w konsoli)."""

    def __init__(self, name: str, missing: str) -> None:
        self.name = name
        self._missing = missing

    def kill(self) -> str:
        raise KillEffectError(f"Nie skonfigurowano: {self._missing}")

    def restore(self) -> str:
        raise KillEffectError(f"Nie skonfigurowano: {self._missing}")
