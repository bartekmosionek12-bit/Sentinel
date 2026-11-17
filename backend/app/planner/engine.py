"""Scan Planner: z faktów o inwentarzu wyprowadza listę akcji skanujących.

Czysty kod bez bazy i bez sieci. Planner niczego nie uruchamia: zwraca plan, a każdą
akcję przed wykonaniem i tak sprawdza `scope_guard`.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.core.scope_guard import Intrusiveness

TRIGGERS = ("sweep", "host_seen", "finding_open")
MODES = ("discover", "services")
HOST_STATES = ("new", "reappeared", "known")
TOOLS = ("nmap",)


@dataclass(frozen=True)
class ScanRule:
    name: str
    description: str
    trigger: str
    tool: str
    mode: str
    intrusiveness: Intrusiveness
    ports: str = "top-1000"
    states: tuple[str, ...] = HOST_STATES
    service_scan_older_than_hours: float | None = None
    in_kev: bool | None = None
    cooldown_hours: float = 0.0


@dataclass(frozen=True)
class HostFact:
    asset_id: uuid.UUID
    address: str
    state: str
    # None = usługi tego hosta nie były jeszcze skanowane
    hours_since_service_scan: float | None = None


@dataclass(frozen=True)
class FindingFact:
    asset_id: uuid.UUID
    address: str
    in_kev: bool
    # Ile godzin temu ta reguła ostatnio zadziałała dla hosta (per nazwa reguły).
    hours_since_rule: dict[str, float]
    # Reguły, których akcja dla tego hosta czeka na zgodę człowieka.
    pending_rules: frozenset[str] = frozenset()


@dataclass(frozen=True)
class PlannedAction:
    rule: str
    tool: str
    mode: str
    target: str
    intrusiveness: Intrusiveness
    reason: str
    ports: str = ""
    asset_id: uuid.UUID | None = None


class ScanPlanner:
    def __init__(self, rules: Sequence[ScanRule]) -> None:
        if len({r.name for r in rules}) != len(rules):
            raise ValueError("Nazwy reguł skanowania muszą być unikalne")
        self._rules = tuple(rules)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanPlanner:
        rules: list[ScanRule] = []
        for item in data.get("rules") or []:
            when = item.get("when") or {}
            older = when.get("service_scan_older_than_hours")
            rule = ScanRule(
                name=str(item["name"]),
                description=str(item.get("description", "")),
                trigger=str(item.get("trigger", "")),
                tool=str(item.get("tool", "")),
                mode=str(item.get("mode", "")),
                intrusiveness=Intrusiveness(int(item.get("intrusiveness", 1))),
                ports=str(item.get("ports", "top-1000")),
                states=tuple(when.get("state") or HOST_STATES),
                service_scan_older_than_hours=float(older) if older is not None else None,
                in_kev=when.get("in_kev"),
                cooldown_hours=float(item.get("cooldown_hours", 0)),
            )
            problems = (
                rule.trigger not in TRIGGERS
                or rule.tool not in TOOLS
                or rule.mode not in MODES
                or rule.intrusiveness >= Intrusiveness.FORBIDDEN
                or bool(set(rule.states) - set(HOST_STATES))
                or (rule.trigger == "sweep") != (rule.mode == "discover")
                # odkrywanie całej sieci nigdy nie jest inwazyjne
                or (rule.mode == "discover" and rule.intrusiveness > Intrusiveness.LIGHT)
            )
            if problems:
                raise ValueError(f"Nieprawidłowa reguła skanowania: {rule.name}")
            rules.append(rule)
        return cls(rules)

    @classmethod
    def from_file(cls, path: Path) -> ScanPlanner:
        return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")) or {})

    def _for(self, trigger: str) -> list[ScanRule]:
        return [r for r in self._rules if r.trigger == trigger]

    def sweep_actions(self, allowed_cidrs: Sequence[str]) -> list[PlannedAction]:
        return [
            PlannedAction(
                rule=rule.name,
                tool=rule.tool,
                mode=rule.mode,
                target=cidr,
                intrusiveness=rule.intrusiveness,
                reason=f"{rule.description}: {cidr} jest na allowliście",
            )
            for rule in self._for("sweep")
            for cidr in allowed_cidrs
        ]

    def host_actions(self, hosts: Sequence[HostFact]) -> list[PlannedAction]:
        actions: list[PlannedAction] = []
        for host in sorted(hosts, key=lambda h: h.address):
            for rule in self._for("host_seen"):
                if host.state not in rule.states:
                    continue
                age = host.hours_since_service_scan
                limit = rule.service_scan_older_than_hours
                if limit is not None and age is not None and age < limit:
                    continue
                if host.state == "known":
                    detail = (
                        "usługi nie były jeszcze skanowane"
                        if age is None
                        else f"ostatni skan usług {age:.0f} h temu"
                    )
                else:
                    detail = "host nowy" if host.state == "new" else "host wrócił do sieci"
                actions.append(
                    PlannedAction(
                        rule=rule.name,
                        tool=rule.tool,
                        mode=rule.mode,
                        target=host.address,
                        intrusiveness=rule.intrusiveness,
                        reason=f"{rule.description}: {detail}",
                        ports=rule.ports,
                        asset_id=host.asset_id,
                    )
                )
                break
        return actions

    def finding_actions(self, facts: Sequence[FindingFact]) -> list[PlannedAction]:
        actions: list[PlannedAction] = []
        for fact in sorted(facts, key=lambda f: f.address):
            for rule in self._for("finding_open"):
                if rule.in_kev is not None and fact.in_kev != rule.in_kev:
                    continue
                if rule.name in fact.pending_rules:
                    continue
                last = fact.hours_since_rule.get(rule.name)
                if last is not None and last < rule.cooldown_hours:
                    continue
                actions.append(
                    PlannedAction(
                        rule=rule.name,
                        tool=rule.tool,
                        mode=rule.mode,
                        target=fact.address,
                        intrusiveness=rule.intrusiveness,
                        reason=rule.description,
                        ports=rule.ports,
                        asset_id=fact.asset_id,
                    )
                )
                break
        return actions
