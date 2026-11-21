"""Ewaluacja dwóch kolejnych zadań modelu: warstwy „W skrócie” raportu i planu agenta.

    cd backend
    uv run python ../eval/run_eval_tasks.py --task report --model qwen3-4b-q4km
    uv run python ../eval/run_eval_tasks.py --task plan --model qwen3-4b-q4km
    uv run python ../eval/run_eval_tasks.py --task plan --model template   # bez modelu

Obie ścieżki to prawdziwy kod aplikacji na fikcyjnych danych (SQLite w pamięci, bez sieci
poza lokalną Ollamą). Model niczego nie decyduje: światło raportu liczy kod, a plan agenta
przechodzi walidator i scope_guard. Ewaluacja mierzy, czy tekst i plan modelu są użyteczne.

Wyniki: eval/results/<zadanie>-<model>.jsonl i podsumowanie na standardowym wyjściu.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.agent.planner import Planner  # noqa: E402
from app.agent.validator import validate_plan  # noqa: E402
from app.agent_tests.cases import load_cases as load_agent_cases  # noqa: E402
from app.agent_tests.harness import NoDnsResolver  # noqa: E402
from app.core.audit import AuditEvent  # noqa: E402
from app.core.scope_guard import InMemoryRateLimiter, ScopeConfig, ScopeGuard  # noqa: E402
from app.explainer.providers import LLMProvider, OllamaProvider  # noqa: E402
from app.models import Asset, Base, Finding, Vulnerability  # noqa: E402
from app.models.base import utcnow  # noqa: E402
from app.pipeline import Rulebook, analyze  # noqa: E402
from app.reports.config import ReportsConfig  # noqa: E402
from app.reports.service import create_report, generate_summary, present  # noqa: E402
from tests.pipeline_helpers import RULES, seed_feeds, seed_inventory  # noqa: E402

AGENT_CASES = ROOT.parent / "ai-tests" / "agent" / "cases.yaml"
SCOPE = RULES / "scope.demo.yaml"


def provider(model: str, url: str) -> LLMProvider | None:
    if model == "template":
        return None
    return OllamaProvider(base_url=url, model=model, num_ctx=4096)


def _session() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _contains(text: str, phrases: list[str]) -> list[str]:
    low = text.lower()
    return [p for p in phrases if p.lower() in low]


def run_report_case(case: dict[str, Any], llm: LLMProvider | None) -> dict[str, Any]:
    session = _session()
    seed_feeds(session)
    seed_inventory(session)
    for name, values in (case.get("assets") or {}).items():
        asset = session.scalar(select(Asset).where(Asset.name == name))
        assert asset is not None, name  # noqa: S101 - błąd w pliku przypadków
        for key, value in values.items():
            setattr(asset, key, value)
    for cve in case.get("drop_kev") or []:
        vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve))
        if vuln is not None:
            vuln.in_kev = False
    analyze(session, Rulebook.from_dir(RULES))
    if case.get("resolve"):
        for finding in session.scalars(select(Finding)):
            finding.status = "resolved"
    session.flush()
    config = ReportsConfig.from_dir(RULES)
    report = create_report(session, config, kind="assessment", actor="eval")
    started = time.monotonic()
    outcome = generate_summary(session, report, config, llm, actor="eval")
    seconds = round(time.monotonic() - started, 1)
    shown = " ".join(i["answer"] for i in present(report, personal=True)["summary"])
    passed = outcome.validation == "passed"
    hits = _contains(shown, case.get("expect") or []) if passed else []
    bad = _contains(shown, case.get("forbid") or []) if passed else []
    session.close()
    return {
        "id": case["id"],
        "light": report.light,
        "light_ok": report.light == case.get("light", report.light),
        "validation": outcome.validation,
        "attempts": outcome.attempts,
        "problems": list(outcome.problems)[:5],
        "expected_hit": bool(hits) if passed else None,
        "forbidden_hit": bad,
        "seconds": seconds,
        "shown": shown[:1200],
    }


def run_plan_case(case: dict[str, Any], llm: LLMProvider | None) -> dict[str, Any]:
    base = load_agent_cases(AGENT_CASES)
    capability = base.capability
    events: list[AuditEvent] = []

    def sink(event: AuditEvent) -> None:
        events.append(event)

    guard = ScopeGuard(
        ScopeConfig.from_file(SCOPE),
        audit=sink,
        resolver=NoDnsResolver(),
        rate_limiter=InMemoryRateLimiter(),
    )
    started = time.monotonic()
    plan = Planner(llm).plan(case["command"], capability, [])
    seconds = round(time.monotonic() - started, 1)
    verdicts = validate_plan(
        plan.steps, capability, guard, killed=False, now=utcnow(), task_id=f"eval:{case['id']}"
    )
    allowed = [v for v in verdicts if v.allowed]
    tools = {v.step.tool for v in allowed}
    targets = {v.step.target for v in allowed}
    return {
        "id": case["id"],
        "source": plan.source,
        "problems": plan.problems[:5],
        "steps": [(v.step.tool, v.step.target, v.level, v.code) for v in verdicts],
        "allowed": len(allowed),
        "blocked": len(verdicts) - len(allowed),
        "tools_ok": set(case.get("expect_tools") or []) <= tools,
        "targets_ok": set(case.get("expect_targets") or []) <= targets,
        "within_steps": len(verdicts) <= int(case.get("max_steps", 99)),
        "unneeded_tools": sorted(tools & set(case.get("forbid_tools") or [])),
        "seconds": seconds,
    }


def summarize(task: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows) or 1
    if task == "report":
        passed = [r for r in rows if r["validation"] == "passed"]
        return {
            "cases": len(rows),
            "light_as_expected": sum(r["light_ok"] for r in rows),
            "validation": dict(Counter(r["validation"] for r in rows)),
            "passed_rate": round(len(passed) / n, 2),
            "first_attempt": sum(1 for r in passed if r["attempts"] == 1),
            "expected_phrase": sum(1 for r in passed if r["expected_hit"]),
            "forbidden_phrase": sum(1 for r in rows if r["forbidden_hit"]),
            "avg_seconds": round(sum(r["seconds"] for r in rows) / n, 1),
        }
    return {
        "cases": len(rows),
        "model_plans": sum(1 for r in rows if r["source"] == "model"),
        "tools_ok": sum(r["tools_ok"] for r in rows),
        "targets_ok": sum(r["targets_ok"] for r in rows),
        "within_steps": sum(r["within_steps"] for r in rows),
        "with_unneeded_tools": sum(1 for r in rows if r["unneeded_tools"]),
        "blocked_steps": sum(r["blocked"] for r in rows),
        "avg_seconds": round(sum(r["seconds"] for r in rows) / n, 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", choices=["report", "plan"], required=True)
    parser.add_argument("--model", default="qwen3-4b-q4km", help="nazwa w Ollamie albo template")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--out", type=Path, default=ROOT / "results")
    args = parser.parse_args()

    cases_file = ROOT / ("report_cases.yaml" if args.task == "report" else "plan_cases.yaml")
    cases = yaml.safe_load(cases_file.read_text(encoding="utf-8"))["cases"]
    llm = provider(args.model, args.ollama_url)
    runner: Callable[[dict[str, Any], LLMProvider | None], dict[str, Any]] = (
        run_report_case if args.task == "report" else run_plan_case
    )
    rows = [runner(case, llm) for case in cases]
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / f"{args.task}-{args.model}.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    summary = summarize(args.task, rows)
    sys.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    # Błąd w przypadku (kod wyliczył inne światło) to błąd zestawu, nie modelu.
    if args.task == "report" and summary["light_as_expected"] != summary["cases"]:
        sys.stderr.write("Światło niezgodne z przypadkiem: popraw report_cases.yaml\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
