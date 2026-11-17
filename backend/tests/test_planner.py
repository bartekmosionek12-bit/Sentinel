"""Scan Planner: te same fakty dają ten sam plan, a każda akcja ma nazwę reguły."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.core.scope_guard import Intrusiveness
from app.planner.engine import FindingFact, HostFact, ScanPlanner
from tests.pipeline_helpers import RULES

PLANNER = ScanPlanner.from_file(RULES / "scan_rules.yaml")
A, B, C = (uuid.UUID(int=n) for n in (1, 2, 3))


def test_sweep_plans_one_discovery_per_allowed_network() -> None:
    actions = PLANNER.sweep_actions(["172.30.99.0/24", "10.0.0.0/28"])
    assert [(a.rule, a.mode, a.target) for a in actions] == [
        ("scope_sweep", "discover", "172.30.99.0/24"),
        ("scope_sweep", "discover", "10.0.0.0/28"),
    ]
    assert all(a.intrusiveness == Intrusiveness.LIGHT for a in actions)
    assert PLANNER.sweep_actions([]) == []


def test_host_rules_scan_new_reappeared_and_stale_hosts_only() -> None:
    hosts = [
        HostFact(A, "172.30.99.12", "known", hours_since_service_scan=2),
        HostFact(B, "172.30.99.11", "known", hours_since_service_scan=30),
        HostFact(C, "172.30.99.10", "new"),
        HostFact(uuid.UUID(int=4), "172.30.99.13", "reappeared", hours_since_service_scan=1),
        HostFact(uuid.UUID(int=5), "172.30.99.14", "known"),
    ]
    actions = PLANNER.host_actions(hosts)
    assert [(a.target, a.rule) for a in actions] == [
        ("172.30.99.10", "new_host_service_scan"),
        ("172.30.99.11", "stale_host_service_rescan"),
        ("172.30.99.13", "new_host_service_scan"),
        ("172.30.99.14", "stale_host_service_rescan"),
    ]
    assert "6379" in actions[0].ports.split(",")
    assert "30 h temu" in actions[1].reason
    assert "nie były jeszcze skanowane" in actions[3].reason
    assert PLANNER.host_actions(list(reversed(hosts))) == actions


def test_kev_finding_proposes_intrusive_scan_with_cooldown_and_no_duplicates() -> None:
    facts = [
        FindingFact(A, "172.30.99.10", True, {}),
        FindingFact(B, "172.30.99.11", False, {}),
        FindingFact(C, "172.30.99.12", True, {"kev_full_port_scan": 5.0}),
        FindingFact(uuid.UUID(int=4), "172.30.99.13", True, {"kev_full_port_scan": 200.0}),
        FindingFact(uuid.UUID(int=5), "172.30.99.14", True, {}, frozenset({"kev_full_port_scan"})),
    ]
    actions = PLANNER.finding_actions(facts)
    assert [a.target for a in actions] == ["172.30.99.10", "172.30.99.13"]
    assert all(a.intrusiveness == Intrusiveness.INTRUSIVE for a in actions)
    assert actions[0].ports == "1-65535"


@pytest.mark.parametrize(
    "rule",
    [
        {"name": "x", "trigger": "cron", "tool": "nmap", "mode": "services"},
        {"name": "x", "trigger": "host_seen", "tool": "metasploit", "mode": "services"},
        {"name": "x", "trigger": "host_seen", "tool": "nmap", "mode": "exploit"},
        {"name": "x", "trigger": "host_seen", "tool": "nmap", "mode": "discover"},
        {"name": "x", "trigger": "sweep", "tool": "nmap", "mode": "discover", "intrusiveness": 2},
        {
            "name": "x",
            "trigger": "host_seen",
            "tool": "nmap",
            "mode": "services",
            "when": {"state": ["haunted"]},
        },
    ],
)
def test_invalid_rules_are_rejected(rule: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="Nieprawidłowa reguła"):
        ScanPlanner.from_dict({"rules": [rule]})


def test_forbidden_intrusiveness_cannot_be_configured() -> None:
    rule = {"name": "x", "trigger": "host_seen", "tool": "nmap", "mode": "services"}
    with pytest.raises(ValueError, match="Nieprawidłowa reguła"):
        ScanPlanner.from_dict({"rules": [{**rule, "intrusiveness": 3}]})
    with pytest.raises(ValueError, match="unikalne"):
        ScanPlanner.from_dict({"rules": [rule, rule]})
