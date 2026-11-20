"""Walidator planu: kod, nie model, decyduje, które kroki w ogóle trafią do człowieka.

Dla każdego kroku: parametry z dozwolonej listy → polityka zdolności (`policy.check_call`, z
licznikiem wywołań w planie) → `scope_guard` na sucho (bez zużywania limitów). Krok odrzucony
dostaje status `blocked` z kodem i powodem; nigdy się nie wykona. Poziom kroku pochodzi z
katalogu, nie z planu.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.agent import policy
from app.agent.capability import Capability
from app.agent.catalog import CATALOG
from app.agent.planner import PlannedStep
from app.core.scope_guard import ApprovalRequired, ScopeError, ScopeGuard

_PORTS_RE = re.compile(r"^(?:top-1000|\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*)$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ALLOWED_PARAMS: dict[str, set[str]] = {
    "discover_hosts": set(),
    "scan_services": {"ports"},
    "scan_all_ports": set(),
    "probe_http": {"port", "scheme"},
    "verify_cve": {"cve_id", "port"},
    "collect_software_authenticated": set(),
}


@dataclass(frozen=True)
class StepVerdict:
    step: PlannedStep
    allowed: bool
    code: str
    reason: str
    level: int
    params: dict[str, Any]


def _port(value: object) -> int | None:
    try:
        port = int(str(value))
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def normalize_params(
    tool: str, params: dict[str, Any], templates_for: Callable[[str], Sequence[str]] | None
) -> tuple[dict[str, Any] | None, str]:
    """Parametry po sprawdzeniu albo (None, powód). Nieznany parametr = odrzucenie."""
    extra = set(params) - ALLOWED_PARAMS.get(tool, set())
    if extra:
        return None, f"Niedozwolone parametry: {', '.join(sorted(extra))}"
    clean: dict[str, Any] = {}
    if tool == "scan_services":
        ports = str(params.get("ports") or "top-1000").replace(" ", "")
        if not _PORTS_RE.match(ports) or ports == "1-65535":
            return None, "Nieprawidłowa lista portów (pełny zakres to narzędzie scan_all_ports)"
        clean["ports"] = ports
    if tool in ("probe_http", "verify_cve"):
        port = _port(params.get("port", 80))
        if port is None:
            return None, "Nieprawidłowy port"
        clean["port"] = port
    if tool == "probe_http":
        scheme = str(params.get("scheme") or "http")
        if scheme not in ("http", "https"):
            return None, "Schemat musi być http albo https"
        clean["scheme"] = scheme
    if tool == "verify_cve":
        cve = str(params.get("cve_id") or "").upper()
        if not _CVE_RE.match(cve):
            return None, "Brak poprawnego identyfikatora CVE"
        if templates_for is not None and not templates_for(cve):
            return None, f"Brak dozwolonego szablonu wykrywającego dla {cve}"
        clean["cve_id"] = cve
    return clean, ""


def validate_plan(
    steps: Sequence[PlannedStep],
    capability: Capability | None,
    guard: ScopeGuard,
    *,
    killed: bool,
    now: datetime,
    task_id: str,
    already: Sequence[tuple[str, str, dict[str, Any]]] = (),
    calls_before: int = 0,
    target_calls_before: Counter[str] | None = None,
    templates_for: Callable[[str], Sequence[str]] | None = None,
) -> list[StepVerdict]:
    verdicts: list[StepVerdict] = []
    seen = {(tool, target, tuple(sorted(params.items()))) for tool, target, params in already}
    calls = calls_before
    per_target: Counter[str] = Counter(target_calls_before or {})
    for position, step in enumerate(steps, start=1):
        spec = CATALOG.get(step.tool)
        level = int(spec.level) if spec else 1
        params, problem = normalize_params(step.tool, dict(step.params), templates_for)
        key = (step.tool, step.target, tuple(sorted((params or {}).items())))
        if spec is not None and params is not None and key in seen:
            verdicts.append(
                StepVerdict(
                    step, False, "duplicate_step", "Ten sam krok jest już w planie", level, params
                )
            )
            continue
        decision = policy.check_call(
            capability,
            step.tool,
            step.target,
            killed=killed,
            now=now,
            calls_in_task=calls,
            calls_for_target=per_target[step.target],
        )
        if not decision.allowed:
            verdicts.append(
                StepVerdict(step, False, decision.code, decision.reason, level, params or {})
            )
            continue
        if params is None:
            verdicts.append(StepVerdict(step, False, "invalid_params", problem, level, {}))
            continue
        if spec is None:  # pragma: no cover - polityka odrzuca nieznane narzędzia wcześniej
            continue
        rule = f"agent-plan:{task_id}:{position}"
        try:
            if spec.target_kind == "network":
                guard.authorize_network(
                    step.target,
                    tool=spec.name,
                    intrusiveness=spec.level,
                    rule_name=rule,
                    dry_run=True,
                )
            else:
                guard.authorize(
                    step.target,
                    tool=spec.name,
                    intrusiveness=spec.level,
                    rule_name=rule,
                    dry_run=True,
                )
        except ApprovalRequired:
            pass  # L2/L3: zgodę wyda człowiek przy zatwierdzaniu planu
        except ScopeError as error:
            verdicts.append(StepVerdict(step, False, error.code, error.reason, level, params))
            continue
        seen.add(key)
        calls += 1
        per_target[step.target] += 1
        reason = "Zgodne ze zdolnościami i zakresem"
        if level >= 2:
            reason += f"; poziom L{level} wymaga zgody administratora"
        verdicts.append(StepVerdict(step, True, policy.ALLOWED, reason, level, params))
    return verdicts
