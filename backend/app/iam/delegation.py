"""Delegacje warstw skanowania: kto, którą warstwę, na jakiej podsieci i do kiedy.

Domyślnie trzy warstwy (docs/WARSTWY.md) uruchamia wyłącznie administrator (rola z `*`).
Administrator może dać konkretnej osobie jedną warstwę na wybranych podsieciach w oknie
czasu. Delegacja:

* działa tylko w oknie `valid_from`–`valid_until` i tylko z MFA (jak uprawnienia z roli),
* dodaje uprawnienie warstwy (`redteam:layerN`); warstwa 3 dodatkowo `agent:task` i
  `agent:read`, bo agent bez nich nie przyjmie polecenia ani zgody na plan,
* ogranicza cele do swoich podsieci: endpoint sprawdza każdy cel (`covers`),
* nigdy nie omija scope_guard: podsieć delegacji musi leżeć w zakresie skanowania,
  a każdy cel i tak przechodzi przez bramę przy skanie.

Nadanie i odwołanie trafiają do audytu. Rola własna nie może zawierać uprawnień warstw
(`RESERVED_PERMISSIONS`), więc jedyną drogą poza administratorem jest delegacja z terminem.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from ipaddress import IPv4Network, IPv6Network, ip_network

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.scope_guard import ScopeConfig
from app.iam.custom_roles import effective_catalog
from app.iam.rbac import RoleCatalog
from app.iam.tokens import Principal
from app.models import LayerDelegation, User
from app.models.base import utcnow

Network = IPv4Network | IPv6Network

LAYERS: dict[int, str] = {1: "redteam:layer1", 2: "redteam:layer2", 3: "redteam:layer3"}
LAYER_NAMES: dict[int, str] = {
    1: "Warstwa 1: skan deterministyczny",
    2: "Warstwa 2: analiza LLM i zalecenia",
    3: "Warstwa 3: autonomiczny agent AI",
}
# Bez tych uprawnień delegowana osoba nie mogłaby wydać agentowi polecenia ani zatwierdzić planu.
EXTRA: dict[int, tuple[str, ...]] = {3: ("agent:task", "agent:read")}
MAX_WINDOW = timedelta(days=30)


class DelegationError(ValueError):
    """Delegacja odrzucona (zła podsieć, okno czasu, konto albo warstwa)."""


@dataclass(frozen=True)
class LayerAccess:
    layer: int
    allowed: bool
    via: str | None  # "rola" | "delegacja" | None
    scope: tuple[str, ...] | None  # None = cały zakres skanowania (administrator)
    until: datetime | None = None
    delegation_id: uuid.UUID | None = None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=utcnow().tzinfo)


def parse_scope(items: Iterable[str]) -> list[Network]:
    networks: list[Network] = []
    for raw in items:
        value = raw.strip()
        if not value:
            continue
        try:
            networks.append(ip_network(value, strict=False))
        except ValueError as error:
            raise DelegationError(f"{value[:60]}: to nie jest adres IP ani podsieć CIDR") from error
    return networks


def covers(scope: Sequence[str] | None, targets: Iterable[str]) -> list[str]:
    """Cele spoza podsieci delegacji (pusta lista = wszystkie w środku). None = bez limitu."""
    if scope is None:
        return []
    allowed = parse_scope(scope)
    outside: list[str] = []
    for target in targets:
        try:
            network = ip_network(target.strip(), strict=False)
        except ValueError:
            outside.append(target)  # delegacja obejmuje wyłącznie adresy i podsieci
            continue
        if not any(
            network.version == a.version and network.subnet_of(a)  # type: ignore[arg-type]
            for a in allowed
        ):
            outside.append(target)
    return outside


def active(session: Session, subject: str, now: datetime | None = None) -> list[LayerDelegation]:
    now = now or utcnow()
    rows = session.scalars(
        select(LayerDelegation)
        .join(User, User.id == LayerDelegation.user_id)
        .where(
            User.subject == subject,
            User.active.is_(True),
            LayerDelegation.revoked_at.is_(None),
        )
    )
    return [row for row in rows if _aware(row.valid_from) <= now < _aware(row.valid_until)]


def apply_delegations(session: Session, principal: Principal) -> Principal:
    """Dokłada uprawnienia z aktywnych delegacji. Tylko ludzie i tylko po MFA."""
    if principal.kind != "human" or not principal.mfa:
        return principal
    rows = active(session, principal.subject)
    if not rows:
        return principal
    extra: set[str] = set()
    for row in rows:
        extra.add(LAYERS[row.layer])
        extra.update(EXTRA.get(row.layer, ()))
    return replace(principal, permissions=principal.permissions | frozenset(extra))


def access(session: Session, catalog: RoleCatalog, principal: Principal, layer: int) -> LayerAccess:
    """Czy wywołujący ma warstwę: z roli (cały zakres) albo z delegacji (jej podsieci)."""
    permission = LAYERS[layer]
    by_role = permission in effective_catalog(session, catalog).resolve(
        principal.roles, mfa=principal.mfa
    )
    if by_role:
        return LayerAccess(layer, True, "rola", None)
    if principal.kind != "human" or not principal.mfa:
        return LayerAccess(layer, False, None, None)
    rows = [row for row in active(session, principal.subject) if row.layer == layer]
    if not rows:
        return LayerAccess(layer, False, None, None)
    scope = tuple(dict.fromkeys(cidr for row in rows for cidr in row.scope))
    latest = max(rows, key=lambda row: _aware(row.valid_until))
    return LayerAccess(layer, True, "delegacja", scope, _aware(latest.valid_until), latest.id)


def delegation_for(
    session: Session, principal: Principal, layer: int, targets: Sequence[str]
) -> LayerDelegation | None:
    """Delegacja, która w całości obejmuje cele (do zapisania przy przebiegu)."""
    for row in active(session, principal.subject):
        if row.layer == layer and not covers(row.scope, targets):
            return row
    return None


def _check_scope(scope: Sequence[str], scan_scope: ScopeConfig) -> list[str]:
    networks = parse_scope(scope)
    if not networks:
        raise DelegationError("Podaj co najmniej jedną podsieć (CIDR) albo adres")
    for network in networks:
        inside = any(
            network.version == allowed.version and network.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in scan_scope.allowed_cidrs
        )
        if not inside:
            raise DelegationError(
                f"{network} nie leży w całości w zakresie skanowania (allowlista scope_guard)"
            )
    return [str(n) for n in networks]


def grant(
    session: Session,
    user: User,
    *,
    layer: int,
    scope: Sequence[str],
    valid_from: datetime,
    valid_until: datetime,
    reason: str,
    actor: str,
    scan_scope: ScopeConfig,
    now: datetime | None = None,
) -> LayerDelegation:
    now = now or utcnow()
    if layer not in LAYERS:
        raise DelegationError("Warstwa musi być 1, 2 albo 3")
    if user.kind != "human":
        raise DelegationError(
            "Delegacje dostają ludzie. Agent AI ma zdolności (zakładka Non-human)"
        )
    if not user.active:
        raise DelegationError(f"Konto {user.username} jest nieaktywne")
    if "administrator" in (user.roles or []):
        raise DelegationError("Administrator ma wszystkie warstwy z roli; delegacja niepotrzebna")
    start, end = _aware(valid_from), _aware(valid_until)
    if end <= start:
        raise DelegationError("Koniec okna musi być po początku")
    if end <= now:
        raise DelegationError("Okno delegacji już minęło")
    if end - start > MAX_WINDOW:
        raise DelegationError("Delegacja może trwać najwyżej 30 dni")
    clean = _check_scope(scope, scan_scope)
    row = LayerDelegation(
        user_id=user.id,
        layer=layer,
        scope=clean,
        valid_from=start,
        valid_until=end,
        reason=reason.strip(),
        granted_by=actor,
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="layer_delegated",
            reason=f"{LAYER_NAMES[layer]} dla {user.username}: {reason.strip()}",
            inputs={
                "user": user.username,
                "layer": layer,
                "scope": clean,
                "valid_from": start.isoformat(),
                "valid_until": end.isoformat(),
            },
            object_type="user",
            object_id=user.subject,
        ),
    )
    return row


def revoke(session: Session, row: LayerDelegation, *, actor: str) -> LayerDelegation:
    if row.revoked_at is not None:
        raise DelegationError("Delegacja jest już odwołana")
    row.revoked_at = utcnow()
    row.revoked_by = actor
    user = session.get(User, row.user_id)
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="layer_delegation_revoked",
            reason=f"Odwołana delegacja: {LAYER_NAMES[row.layer]}"
            + (f" dla {user.username}" if user else ""),
            inputs={"layer": row.layer, "scope": list(row.scope)},
            object_type="user",
            object_id=user.subject if user else str(row.user_id),
        ),
    )
    return row


def state(row: LayerDelegation, now: datetime | None = None) -> str:
    now = now or utcnow()
    if row.revoked_at is not None:
        return "odwołana"
    if now < _aware(row.valid_from):
        return "zaplanowana"
    if now >= _aware(row.valid_until):
        return "wygasła"
    return "aktywna"
