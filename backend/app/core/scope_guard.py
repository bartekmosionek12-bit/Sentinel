"""scope_guard: jedyna brama dla aktywnych działań sieciowych.

Zasady (docs/ARCHITECTURE.md, sekcja 3):

* tylko ten moduł potrafi wydać `ScopedTarget`; adaptery narzędzi przyjmują
  wyłącznie `ScopedTarget`, więc nie da się skanować z pominięciem bramy,
* allowlista domen i CIDR pochodzi z konfiguracji i domyślnie jest pusta,
* denylista ma pierwszeństwo przed allowlistą,
* nazwa domenowa jest sprawdzana także po rozwiązaniu DNS, a do narzędzia
  trafia już adres IP,
* poziom L2 wymaga zgody człowieka; zgoda `seed_demo` zastępuje kliknięcie
  wyłącznie przy DEMO_MODE=true, w CIDR sieci demo-lab i przed wygaśnięciem,
* każda decyzja, pozytywna i negatywna, trafia do audit logu.
"""

from __future__ import annotations

import re
import socket
import time
from collections import defaultdict, deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path
from typing import Any, Final, Protocol

import yaml

from app.core.audit import AuditEvent, AuditSink

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

_HOSTNAME_RE: Final = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$"
)
_SEAL: Final = object()
SEED_DEMO_SOURCE: Final = "seed_demo"


class Intrusiveness(IntEnum):
    LIGHT = 1  # L1: pasywne i lekkie (feedy, dnsx, httpx, nmap -sV, szablony info)
    INTRUSIVE = 2  # L2: pełny skan, weryfikacja podatności, skan uwierzytelniony; zgoda admina
    REDTEAM = 3  # L3: aktywny red team systemów AI; zgoda admina z osobnym uprawnieniem
    FORBIDDEN = 4  # eksploatacja, DoS, brute force: nigdy


class ScopeError(Exception):
    """Bazowy wyjątek bramy. Każdy oznacza: akcja NIE może się wykonać."""

    code = "scope_error"

    def __init__(self, target: str, reason: str) -> None:
        super().__init__(f"{target}: {reason}")
        self.target = target
        self.reason = reason


class ScopeDenied(ScopeError):
    code = "scope_denied"


class ApprovalRequired(ScopeError):
    code = "scope_awaiting_approval"


class RateLimited(ScopeError):
    code = "scope_rate_limited"


@dataclass(frozen=True)
class HumanApproval:
    """Zgoda człowieka na akcję L2: kto i dlaczego."""

    approved_by: str
    reason: str


@dataclass(frozen=True)
class ScopedTarget:
    """Cel, który przeszedł przez `ScopeGuard`. Nie da się go utworzyć inaczej."""

    original: str
    ip: IPAddress
    hostname: str | None
    tool: str
    intrusiveness: Intrusiveness
    rule_name: str
    approval_source: str | None = None
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("ScopedTarget może wydać wyłącznie ScopeGuard.authorize()")

    @property
    def address(self) -> str:
        """Adres przekazywany narzędziu: zawsze IP sprawdzone przez bramę."""
        return str(self.ip)


@dataclass(frozen=True)
class ScopedNetwork:
    """Sieć do odkrywania hostów, która przeszła przez `ScopeGuard`.

    `excluded` to adresy z denylisty leżące wewnątrz sieci; narzędzie musi je pominąć.
    """

    network: IPNetwork
    excluded: tuple[IPNetwork, ...]
    tool: str
    intrusiveness: Intrusiveness
    rule_name: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("ScopedNetwork może wydać wyłącznie ScopeGuard.authorize_network()")

    @property
    def address(self) -> str:
        return str(self.network)


def require_scoped(target: object) -> ScopedTarget:
    """Strażnik dla adapterów: odrzuca wszystko, co nie jest `ScopedTarget`."""
    if not isinstance(target, ScopedTarget):
        raise TypeError(
            "Adapter przyjmuje wyłącznie ScopedTarget wydany przez scope_guard, "
            f"otrzymano {type(target).__name__}"
        )
    return target


@dataclass(frozen=True)
class ScopeConfig:
    allowed_domains: tuple[str, ...] = ()
    allowed_cidrs: tuple[IPNetwork, ...] = ()
    denied_domains: tuple[str, ...] = ()
    denied_cidrs: tuple[IPNetwork, ...] = ()
    default_rate_per_minute: int = 30
    rate_per_target: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ScopeConfig:
        data = data or {}
        allow = data.get("allow") or {}
        deny = data.get("deny") or {}
        rates = data.get("rate_limits") or {}
        return cls(
            allowed_domains=_domains(allow.get("domains")),
            allowed_cidrs=_networks(allow.get("cidrs")),
            denied_domains=_domains(deny.get("domains")),
            denied_cidrs=_networks(deny.get("cidrs")),
            default_rate_per_minute=int(rates.get("default_per_minute", 30)),
            rate_per_target={
                str(k).lower(): int(v) for k, v in (rates.get("per_target") or {}).items()
            },
        )

    @classmethod
    def from_file(cls, path: Path) -> ScopeConfig:
        """Brak pliku oznacza pusty zakres, czyli nic nie jest dozwolone."""
        if not path.exists():
            return cls()
        with path.open(encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle)
        if loaded is not None and not isinstance(loaded, dict):
            raise ValueError(f"{path}: oczekiwano mapy YAML")
        return cls.from_dict(loaded)

    def rate_for(self, key: str) -> int:
        return self.rate_per_target.get(key.lower(), self.default_rate_per_minute)


def _domains(values: Sequence[str] | None) -> tuple[str, ...]:
    result: list[str] = []
    for raw in values or ():
        value = str(raw).strip().lower().rstrip(".")
        bare = value.removeprefix("*.")
        if not bare or "*" in bare or not _HOSTNAME_RE.match(bare):
            raise ValueError(f"Nieprawidłowy wzorzec domeny w zakresie: {raw!r}")
        result.append(value)
    return tuple(result)


def _networks(values: Sequence[str] | None) -> tuple[IPNetwork, ...]:
    return tuple(ip_network(str(v).strip(), strict=True) for v in values or ())


def domain_matches(hostname: str, pattern: str) -> bool:
    """`example.lab` pasuje tylko dokładnie; `*.example.lab` tylko do subdomen."""
    if pattern.startswith("*."):
        return hostname.endswith(pattern[1:]) and hostname != pattern[2:]
    return hostname == pattern


class Resolver(Protocol):
    def resolve(self, hostname: str) -> list[IPAddress]: ...


class SystemResolver:
    def resolve(self, hostname: str) -> list[IPAddress]:
        try:
            infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except OSError:
            return []
        return sorted({ip_address(info[4][0]) for info in infos}, key=str)


class RateLimiter(Protocol):
    def acquire(self, key: str, limit_per_minute: int) -> bool: ...


class InMemoryRateLimiter:
    """Okno przesuwne 60 s na klucz. W wielu procesach zastępuje go wersja na Redisie."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def acquire(self, key: str, limit_per_minute: int) -> bool:
        if limit_per_minute <= 0:
            return False
        now = self._clock()
        events = self._events[key]
        while events and now - events[0] >= 60.0:
            events.popleft()
        if len(events) >= limit_per_minute:
            return False
        events.append(now)
        return True


@dataclass(frozen=True)
class SeedDemoApproval:
    """Zgoda `seed_demo` na L2. Zastępuje kliknięcie, nie omija bramy.

    Działa tylko, gdy jednocześnie: DEMO_MODE=true, zgoda ma datę wygaśnięcia
    w przyszłości i KAŻDY adres celu leży w CIDR sieci demo-lab. Zakres zgody
    jest porównywany z CIDR laboratorium, a nie z allowlistą użytkownika.
    """

    demo_mode: bool
    lab_network: IPNetwork
    expires_at: datetime | None

    def covers(self, addresses: Sequence[IPAddress], now: datetime) -> bool:
        if not self.demo_mode or self.expires_at is None or not addresses:
            return False
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if now >= expires:
            return False
        return all(_in_network(addr, self.lab_network) for addr in addresses)


def _in_network(addr: IPAddress, network: IPNetwork) -> bool:
    return addr.version == network.version and addr in network


def _in_any(addr: IPAddress, networks: Sequence[IPNetwork]) -> bool:
    return any(_in_network(addr, net) for net in networks)


class ScopeGuard:
    def __init__(
        self,
        config: ScopeConfig,
        *,
        audit: AuditSink,
        resolver: Resolver | None = None,
        rate_limiter: RateLimiter | None = None,
        seed_demo: SeedDemoApproval | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._config = config
        self._audit = audit
        self._resolver = resolver or SystemResolver()
        self._rate_limiter = rate_limiter or InMemoryRateLimiter()
        self._seed_demo = seed_demo
        self._clock = clock

    @property
    def config(self) -> ScopeConfig:
        return self._config

    def authorize(
        self,
        target: str,
        *,
        tool: str,
        intrusiveness: Intrusiveness,
        rule_name: str,
        approval: HumanApproval | None = None,
        dry_run: bool = False,
    ) -> ScopedTarget:
        """Zwraca `ScopedTarget` albo rzuca `ScopeError`. Zawsze zapisuje decyzję.

        `dry_run=True` (podgląd w UI) sprawdza zakres bez zużywania limitu szybkości.
        """
        context: dict[str, Any] = {
            "target": target,
            "tool": tool,
            "intrusiveness": int(intrusiveness),
            "rule": rule_name,
            "dry_run": dry_run,
        }
        try:
            scoped = self._decide(
                target, tool, intrusiveness, rule_name, approval, dry_run, context
            )
        except ScopeError as error:
            self._audit(
                AuditEvent(
                    actor=f"rule:{rule_name}",
                    action=error.code,
                    reason=error.reason,
                    inputs=context,
                    object_type="target",
                    object_id=target[:255],
                )
            )
            raise
        self._audit(
            AuditEvent(
                actor=f"rule:{rule_name}",
                action="scope_allowed",
                reason="Cel w zakresie, wymagane zgody i limity spełnione",
                inputs=context,
                object_type="target",
                object_id=target[:255],
            )
        )
        return scoped

    def authorize_network(
        self,
        cidr: str,
        *,
        tool: str,
        intrusiveness: Intrusiveness,
        rule_name: str,
        max_addresses: int = 1024,
        dry_run: bool = False,
    ) -> ScopedNetwork:
        """Zgoda na odkrywanie hostów w sieci. Tylko poziom L1.

        Sieć musi w całości leżeć w jednym dozwolonym CIDR. Adresy z denylisty
        wewnątrz sieci trafiają do `excluded` i narzędzie je pomija.
        """
        context: dict[str, Any] = {
            "target": cidr,
            "tool": tool,
            "intrusiveness": int(intrusiveness),
            "rule": rule_name,
            "dry_run": dry_run,
        }
        try:
            scoped = self._decide_network(
                cidr, tool, intrusiveness, rule_name, max_addresses, dry_run
            )
        except ScopeError as error:
            self._audit(
                AuditEvent(
                    actor=f"rule:{rule_name}",
                    action=error.code,
                    reason=error.reason,
                    inputs=context,
                    object_type="network",
                    object_id=cidr[:255],
                )
            )
            raise
        context["excluded"] = [str(n) for n in scoped.excluded]
        self._audit(
            AuditEvent(
                actor=f"rule:{rule_name}",
                action="scope_allowed",
                reason="Sieć w zakresie, wykluczenia przekazane narzędziu",
                inputs=context,
                object_type="network",
                object_id=cidr[:255],
            )
        )
        return scoped

    def _decide_network(
        self,
        cidr: str,
        tool: str,
        intrusiveness: Intrusiveness,
        rule_name: str,
        max_addresses: int,
        dry_run: bool = False,
    ) -> ScopedNetwork:
        if intrusiveness > Intrusiveness.LIGHT:
            raise ScopeDenied(cidr, "Odkrywanie całej sieci jest dozwolone tylko na poziomie L1")
        try:
            network = ip_network(cidr.strip(), strict=True)
        except ValueError as error:
            raise ScopeDenied(cidr, "Cel nie jest poprawnym zakresem CIDR") from error
        if network.num_addresses > max_addresses:
            raise ScopeDenied(cidr, f"Sieć większa niż {max_addresses} adresów")
        if not any(
            network.version == allowed.version and network.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in self._config.allowed_cidrs
        ):
            raise ScopeDenied(cidr, "Sieć nie mieści się w żadnym dozwolonym zakresie CIDR")
        excluded: list[IPNetwork] = []
        for denied in self._config.denied_cidrs:
            if denied.version != network.version or not denied.overlaps(network):
                continue
            if network.subnet_of(denied):  # type: ignore[arg-type]
                raise ScopeDenied(cidr, "Cała sieć jest na denyliście")
            excluded.append(denied)
        if not dry_run and not self._rate_limiter.acquire(
            str(network), self._config.rate_for(str(network))
        ):
            raise RateLimited(cidr, "Przekroczony limit akcji na minutę dla sieci")
        return ScopedNetwork(
            network=network,
            excluded=tuple(excluded),
            tool=tool,
            intrusiveness=intrusiveness,
            rule_name=rule_name,
            _seal=_SEAL,
        )

    def _decide(
        self,
        target: str,
        tool: str,
        intrusiveness: Intrusiveness,
        rule_name: str,
        approval: HumanApproval | None,
        dry_run: bool,
        context: dict[str, Any],
    ) -> ScopedTarget:
        if intrusiveness >= Intrusiveness.FORBIDDEN:
            raise ScopeDenied(target, "Poziom inwazyjności zabroniony: system nie eksploatuje")

        hostname, addresses = self._resolve_target(target)
        context["hostname"] = hostname
        context["resolved"] = [str(a) for a in addresses]

        for addr in addresses:
            if _in_any(addr, self._config.denied_cidrs):
                raise ScopeDenied(target, f"Adres {addr} jest na denyliście")
        for addr in addresses:
            if not _in_any(addr, self._config.allowed_cidrs):
                raise ScopeDenied(target, f"Adres {addr} jest poza dozwolonymi zakresami CIDR")

        approval_source: str | None = None
        if intrusiveness >= Intrusiveness.INTRUSIVE:
            now = self._clock()
            if approval is not None:
                if not approval.approved_by.strip() or not approval.reason.strip():
                    raise ApprovalRequired(target, "Zgoda musi wskazywać osobę i powód")
                approval_source = f"human:{approval.approved_by}"
                context["approval_reason"] = approval.reason
            elif self._seed_demo is not None and self._seed_demo.covers(addresses, now):
                approval_source = SEED_DEMO_SOURCE
                context["approval_expires_at"] = self._seed_demo.expires_at
            else:
                raise ApprovalRequired(
                    target, f"Akcja L{int(intrusiveness)} wymaga zatwierdzenia przez człowieka"
                )
            context["approval_source"] = approval_source

        pinned = addresses[0]
        if not dry_run:
            limit = self._config.rate_for(hostname or str(pinned))
            if not self._rate_limiter.acquire(str(pinned), limit):
                raise RateLimited(target, f"Przekroczony limit {limit} akcji na minutę dla celu")

        return ScopedTarget(
            original=target,
            ip=pinned,
            hostname=hostname,
            tool=tool,
            intrusiveness=intrusiveness,
            rule_name=rule_name,
            approval_source=approval_source,
            _seal=_SEAL,
        )

    def _resolve_target(self, target: str) -> tuple[str | None, list[IPAddress]]:
        value = target.strip().lower().rstrip(".")
        if not value:
            raise ScopeDenied(target, "Pusty cel")
        try:
            return None, [ip_address(value)]
        except ValueError:
            pass
        if not _HOSTNAME_RE.match(value):
            raise ScopeDenied(target, "Cel nie jest adresem IP ani poprawną nazwą hosta")
        if any(domain_matches(value, p) for p in self._config.denied_domains):
            raise ScopeDenied(target, "Domena jest na denyliście")
        if not any(domain_matches(value, p) for p in self._config.allowed_domains):
            raise ScopeDenied(target, "Domena jest poza allowlistą")
        addresses = sorted(set(self._resolver.resolve(value)), key=str)
        if not addresses:
            raise ScopeDenied(target, "Domena nie rozwiązuje się na żaden adres")
        return value, addresses
