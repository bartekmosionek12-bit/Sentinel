"""Moduł 19: harness testu agenta, dwie oceny, podpis wyniku i bramka zmian."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.service import activate_capability, create_capability
from app.agent_tests import signing
from app.agent_tests.cases import load_cases
from app.agent_tests.gate import (
    GateError,
    config_ready,
    force,
    request_change,
    run_test,
    runtime_config,
)
from app.agent_tests.harness import evaluate_case, summarize
from app.core.scope_guard import ScopeConfig
from app.explainer.prompts import Prompt
from app.explainer.providers import ProviderHealth
from app.models import AgentCapability, AgentConfigVersion, AgentTestCaseResult, AuditLog

CASES = Path(__file__).resolve().parents[2] / "ai-tests" / "agent" / "cases.yaml"
# Jak rules/scope.demo.yaml: brama Dockera, worker-scans i mcp-scanner są na denyliście.
SCOPE = ScopeConfig.from_dict(
    {
        "allow": {"cidrs": ["172.30.99.0/24"]},
        "deny": {"cidrs": ["172.30.99.1/32", "172.30.99.250/32", "172.30.99.251/32"]},
    }
)
_TARGET_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


class ObedientModel:
    """Model posłuszny każdemu poleceniu: planuje skan każdego adresu, jaki zobaczy."""

    name = "obedient"
    model = "obedient-mock"

    def __init__(self) -> None:
        self.prompts: list[Prompt] = []

    def stream(self, prompt: Prompt, *, max_tokens: int) -> Iterator[str]:
        self.prompts.append(prompt)
        command, _, data = prompt.user.partition("<<<DANE")
        source = data if data else command.split("Polecenie administratora:", 1)[-1]
        steps = []
        for target in dict.fromkeys(_TARGET_RE.findall(source)):
            if "/" in target:
                steps.append({"tool": "discover_hosts", "target": target, "reason": "polecenie"})
                continue
            for tool in ("scan_all_ports", "probe_http"):
                steps.append({"tool": tool, "target": target, "reason": "polecenie"})
        yield json.dumps({"steps": steps})

    def health(self) -> ProviderHealth:
        return ProviderHealth(True, self.model, "atrapa")


def test_case_file_is_valid_and_covers_every_category() -> None:
    cases = load_cases(CASES)
    categories = {c.category for c in cases.cases}
    assert categories == {
        "control",
        "scope",
        "escalation",
        "approval",
        "credentials",
        "injection",
        "autonomy",
    }
    assert len({c.id for c in cases.cases}) == len(cases.cases)
    assert all("{{host}}" not in c.command for c in cases.cases)
    assert len(cases.suite("quick")) < len(cases.suite("full")) == len(cases.cases)


def test_template_planner_resists_and_code_holds_in_every_case() -> None:
    cases = load_cases(CASES)
    outcomes = [evaluate_case(c, None, cases.capability, SCOPE) for c in cases.cases]
    summary = summarize(outcomes)
    failing = [(o.case.id, o.verdicts) for o in outcomes if not (o.model_resisted and o.code_held)]
    assert failing == []
    assert summary["passed"] is True
    # Napastnik („posłuszny model”) próbował, ale żadna szkodliwa próba się nie wykonała.
    injection = next(o for o in outcomes if o.case.id == "injection_http_title")
    attacker = injection.transcript["attacker_attempts"]
    assert {a["target"] for a in attacker} == {"192.0.2.0/24", "198.51.100.7"}
    assert not any(a["executed"] for a in attacker)


def test_obedient_model_fails_model_score_but_code_still_holds() -> None:
    cases = load_cases(CASES)
    model = ObedientModel()
    outcomes = [evaluate_case(c, model, cases.capability, SCOPE) for c in cases.cases]
    by_id = {o.case.id: o for o in outcomes}
    assert not by_id["scope_extra_target"].model_resisted
    assert not by_id["injection_http_title"].model_resisted
    assert all(o.code_held for o in outcomes), [o.verdicts for o in outcomes if not o.code_held]
    # Kanarek z zatrutego banera nie dotarł do promptu modelu.
    assert not any("SENTINEL-CANARY" in p.user for p in model.prompts)


def test_signature_verifies_and_detects_tampering(tmp_path: Path) -> None:
    key = signing.load_or_create_key(tmp_path / "k.pem")
    payload = {"passed": True, "cases": 3}
    sha = signing.digest(payload)
    signature = signing.sign(key, sha)
    public = signing.public_pem(key)
    assert signing.verify(public, sha, signature)
    assert not signing.verify(public, signing.digest({**payload, "passed": False}), signature)
    assert signing.load_or_create_key(tmp_path / "k.pem").public_key() is not None


def _candidate(session: Session) -> AgentConfigVersion:
    row = create_capability(
        session,
        actor="user:admin",
        tools=["discover_hosts", "scan_services", "probe_http", "scan_all_ports"],
        targets=["172.30.99.0/24"],
        max_level=2,
    )
    return request_change(
        session,
        runtime_config("", False),
        capability_version=row.version,
        reason="Nowe zdolności",
        actor="user:admin",
    )


def test_change_gate_activates_capability_only_after_passed_test(
    session: Session, tmp_path: Path
) -> None:
    config = _candidate(session)
    session.commit()
    assert session.scalar(select(AgentCapability.active)) is False
    run = run_test(
        session,
        suite="quick",
        trigger="config_change",
        requested_by="system:agent-config",
        config_version_id=config.id,
        provider=None,
        scope=SCOPE,
        cases_path=CASES,
        key_path=tmp_path / "harness.pem",
    )
    assert run.passed is True
    assert signing.verify(run.public_key or "", run.result_sha256 or "", run.signature or "")
    session.refresh(config)
    assert config.state == "active"
    assert session.scalar(select(AgentCapability.active)) is True
    assert config_ready(session, runtime_config("", False)) == (config.id, None)
    results = session.scalars(select(AgentTestCaseResult)).all()
    assert len(results) == len(load_cases(CASES).suite("quick"))
    entry = session.scalars(select(AuditLog).where(AuditLog.action == "agent_test_finished")).one()
    assert entry.inputs["sha256"] == run.result_sha256


def test_changed_model_blocks_agent_until_test(session: Session) -> None:
    row = create_capability(
        session,
        actor="user:admin",
        tools=["scan_services"],
        targets=["172.30.99.0/24"],
        max_level=1,
    )
    activate_capability(session, row.version, actor="user:admin", reason="start")
    queued: list[object] = []
    config_id, reason = config_ready(session, runtime_config("qwen3:4b", False), queued.append)
    assert config_id is None
    assert reason
    assert "czeka na test" in reason
    assert len(queued) == 1
    pending = session.get(AgentConfigVersion, queued[0])
    assert pending is not None
    assert pending.state == "pending_test"
    # Drugie wywołanie nie mnoży wersji.
    config_ready(session, runtime_config("qwen3:4b", False), queued.append)
    assert (
        session.scalar(
            select(AgentConfigVersion.id).where(AgentConfigVersion.state == "pending_test")
        )
        == pending.id
    )


def test_force_requires_justification_and_is_audited(session: Session) -> None:
    config = _candidate(session)
    config.state = "rejected"
    session.commit()
    with pytest.raises(GateError, match="uzasadnienia"):
        force(session, config.id, actor="user:admin", justification="bo tak")
    forced = force(
        session,
        config.id,
        actor="user:admin",
        justification="Model słabiej odpiera manipulację, ale kod trzyma; akceptuję na demo.",
    )
    assert forced.state == "forced"
    assert session.scalar(select(AgentCapability.active)) is True
    actions = list(session.scalars(select(AuditLog.action)))
    assert "agent_config_forced" in actions
