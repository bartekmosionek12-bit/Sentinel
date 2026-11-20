"""Polityka narzędzi agenta: czysta funkcja, ta sama dla walidatora planu i serwera MCP.

Kolejność (ARCHITECTURE §5.1): kill switch → narzędzie z katalogu → zdolność → poziom →
cel w zdolnościach → okno czasowe → limity. Dopiero po niej `scope_guard` sprawdza zakres
organizacji, zgodę na L2/L3 i limit szybkości per cel. Polityka nigdy nie ufa poziomowi z
planu: poziom pochodzi z katalogu narzędzi.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.agent.capability import Capability
from app.agent.catalog import CATALOG, ToolSpec


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    spec: ToolSpec | None = None


ALLOWED = "policy_allowed"


def check_call(
    capability: Capability | None,
    tool: str,
    target: str,
    *,
    killed: bool,
    now: datetime,
    calls_in_task: int = 0,
    calls_for_target: int = 0,
) -> PolicyDecision:
    if killed:
        return PolicyDecision(False, "agent_killed", "Agent jest wyłączony (kill switch)")
    spec = CATALOG.get(tool)
    if spec is None:
        return PolicyDecision(False, "unknown_tool", f"Narzędzia {tool!r} nie ma w katalogu")
    if capability is None:
        return PolicyDecision(False, "no_capability", "Agent nie ma aktywnych zdolności", spec)
    if tool not in capability.tools:
        return PolicyDecision(
            False, "tool_not_granted", f"Agent nie ma zdolności do narzędzia {tool}", spec
        )
    if int(spec.level) > capability.max_level:
        return PolicyDecision(
            False,
            "level_exceeds_capability",
            f"Narzędzie {tool} ma poziom L{int(spec.level)}, a zdolności pozwalają "
            f"najwyżej na L{capability.max_level}",
            spec,
        )
    if spec.target_kind == "host" and "/" in target:
        return PolicyDecision(
            False, "invalid_target", f"Narzędzie {tool} przyjmuje pojedynczy host, nie sieć", spec
        )
    if not capability.covers_target(target):
        return PolicyDecision(
            False,
            "target_outside_capability",
            f"Cel {target} jest poza zakresem nadanym agentowi",
            spec,
        )
    if not capability.in_window(now):
        return PolicyDecision(False, "outside_window", "Poza oknem czasowym zdolności agenta", spec)
    if calls_in_task >= capability.max_calls_per_task:
        return PolicyDecision(
            False,
            "task_call_limit",
            f"Limit {capability.max_calls_per_task} wywołań na zadanie wyczerpany",
            spec,
        )
    if calls_for_target >= capability.max_calls_per_target:
        return PolicyDecision(
            False,
            "target_call_limit",
            f"Limit {capability.max_calls_per_target} wywołań na cel wyczerpany",
            spec,
        )
    return PolicyDecision(True, ALLOWED, "Zgodne ze zdolnościami agenta", spec)
