"""Zdolności agenta jako niezmienna wartość, wczytana z aktywnej wersji w bazie."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, time
from ipaddress import ip_address, ip_network
from typing import Any

from app.agent.catalog import CATALOG
from app.core.scope_guard import domain_matches
from app.models import AgentCapability


class CapabilityError(ValueError):
    """Zdolności są niepoprawne (np. narzędzie spoza katalogu)."""


@dataclass(frozen=True)
class Window:
    days: tuple[int, ...]  # 0 = poniedziałek
    start: time
    end: time

    def covers(self, moment: datetime) -> bool:
        clock = moment.timetz().replace(tzinfo=None)
        return moment.weekday() in self.days and self.start <= clock < self.end


@dataclass(frozen=True)
class Capability:
    version: int
    tools: frozenset[str]
    targets: tuple[str, ...]
    max_level: int
    windows: tuple[Window, ...] = ()
    max_calls_per_task: int = 20
    max_calls_per_target: int = 5
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_model(cls, row: AgentCapability) -> Capability:
        return cls.build(
            version=row.version,
            tools=row.tools,
            targets=row.targets,
            max_level=row.max_level,
            windows=row.windows,
            max_calls_per_task=row.max_calls_per_task,
            max_calls_per_target=row.max_calls_per_target,
        )

    @classmethod
    def build(
        cls,
        *,
        version: int,
        tools: Sequence[str],
        targets: Sequence[str],
        max_level: int,
        windows: Sequence[Any] = (),
        max_calls_per_task: int = 20,
        max_calls_per_target: int = 5,
    ) -> Capability:
        unknown = sorted(set(tools) - set(CATALOG))
        if unknown:
            raise CapabilityError(f"Narzędzia spoza katalogu: {', '.join(unknown)}")
        if not 1 <= int(max_level) <= 3:
            raise CapabilityError("Maksymalny poziom musi być z zakresu 1–3")
        for target in targets:
            _check_target_pattern(str(target))
        parsed = []
        for item in windows:
            try:
                parsed.append(
                    Window(
                        tuple(int(d) for d in item.get("days", range(7))),
                        time.fromisoformat(str(item["from"])),
                        time.fromisoformat(str(item["to"])),
                    )
                )
            except (KeyError, ValueError, TypeError, AttributeError) as error:
                raise CapabilityError(f"Nieprawidłowe okno czasowe: {item!r}") from error
        return cls(
            version=int(version),
            tools=frozenset(tools),
            targets=tuple(str(t) for t in targets),
            max_level=int(max_level),
            windows=tuple(parsed),
            max_calls_per_task=int(max_calls_per_task),
            max_calls_per_target=int(max_calls_per_target),
        )

    def covers_target(self, target: str) -> bool:
        """Cel (IP, nazwa albo CIDR) w całości mieści się w zdolnościach."""
        value = target.strip().lower().rstrip(".")
        try:
            network = ip_network(value, strict=False)
        except ValueError:
            return any(
                domain_matches(value, pattern)
                for pattern in self.targets
                if not _is_network(pattern)
            )
        for pattern in self.targets:
            if not _is_network(pattern):
                continue
            allowed = ip_network(pattern, strict=False)
            if allowed.version == network.version and network.subnet_of(allowed):  # type: ignore[arg-type]
                return True
        return False

    def in_window(self, moment: datetime) -> bool:
        return not self.windows or any(w.covers(moment) for w in self.windows)


def _is_network(pattern: str) -> bool:
    try:
        ip_network(pattern, strict=False)
    except ValueError:
        return False
    return True


def _check_target_pattern(pattern: str) -> None:
    if _is_network(pattern):
        return
    try:
        ip_address(pattern)
    except ValueError:
        value = pattern.removeprefix("*.")
        if not value or " " in value or "/" in value:
            raise CapabilityError(f"Nieprawidłowy cel w zdolnościach: {pattern!r}") from None
