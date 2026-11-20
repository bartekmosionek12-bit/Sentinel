"""Przypadki testu agenta z `ai-tests/agent/cases.yaml`."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network
from itertools import islice
from pathlib import Path
from typing import Any

import yaml

from app.agent.capability import Capability


@dataclass(frozen=True)
class AttackStep:
    round: str  # plan | follow_up
    tool: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentCase:
    id: str
    category: str
    title: str
    suite: str
    command: str
    results: dict[str, Any] = field(default_factory=dict)
    attacker_steps: tuple[AttackStep, ...] = ()
    forbidden_targets: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    forbidden_params: tuple[str, ...] = ()
    check_target_limit: bool = False
    # False: przypadek sprawdza tylko kod (np. denylista, której model nie zna).
    judge_model: bool = True
    expect_allowed: bool = False


@dataclass(frozen=True)
class CaseFile:
    capability: Capability
    cases: tuple[AgentCase, ...]

    def suite(self, name: str) -> list[AgentCase]:
        return [c for c in self.cases if name == "full" or c.suite == "quick"]


DEFAULT_HOST = "172.30.99.10"


def host_for(capability: Capability) -> str:
    """Host w zakresie zdolności: dziesiąty adres pierwszej sieci albo pierwsza domena."""
    for pattern in capability.targets:
        try:
            network = ip_network(pattern, strict=False)
        except ValueError:
            continue
        hosts = list(islice(network.hosts(), 10))
        if hosts:
            return str(hosts[-1])
    for pattern in capability.targets:
        if not pattern.startswith("*"):
            return pattern
    return DEFAULT_HOST


def load_cases(path: Path, host: str = DEFAULT_HOST) -> CaseFile:
    text = path.read_text(encoding="utf-8").replace("{{host}}", host)
    data = yaml.safe_load(text) or {}
    cap = data.get("capability") or {}
    capability = Capability.build(
        version=0,
        tools=cap.get("tools", []),
        targets=cap.get("targets", []),
        max_level=int(cap.get("max_level", 1)),
        max_calls_per_task=int(cap.get("max_calls_per_task", 20)),
        max_calls_per_target=int(cap.get("max_calls_per_target", 5)),
    )
    cases = []
    for item in data.get("cases") or []:
        cases.append(
            AgentCase(
                id=str(item["id"]),
                category=str(item["category"]),
                title=str(item["title"]),
                suite=str(item.get("suite", "full")),
                command=" ".join(str(item["command"]).split()),
                results=dict(item.get("results") or {}),
                attacker_steps=tuple(
                    AttackStep(
                        str(s.get("round", "plan")),
                        str(s["tool"]),
                        str(s["target"]),
                        dict(s.get("params") or {}),
                    )
                    for s in item.get("attacker_steps") or []
                ),
                forbidden_targets=tuple(str(t) for t in item.get("forbidden_targets") or []),
                forbidden_tools=tuple(str(t) for t in item.get("forbidden_tools") or []),
                forbidden_params=tuple(str(t) for t in item.get("forbidden_params") or []),
                check_target_limit=bool(item.get("check_target_limit", False)),
                judge_model=bool(item.get("judge_model", True)),
                expect_allowed=bool(item.get("expect_allowed", False)),
            )
        )
    return CaseFile(capability, tuple(cases))
