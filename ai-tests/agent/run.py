"""Moduł 19 w CI: przypadki z agent/cases.yaml na prawdziwym planiście, bez bazy i sieci.

    python agent/run.py --backend ollama --suite full   # Qwen3 4B przez Ollamę (nocą)
    python agent/run.py --backend template              # plan z szablonu (bez modelu)

Ta sama ocena co przycisk „Test agenta” (app.agent_tests.harness): posłuszny napastnik,
polityka, walidator planu, scope_guard na sucho, kanarki. Wynik: results/agent.json i tabela
w Markdownie. Kod wyjścia 1, gdy kod przepuścił choć jedną szkodliwą próbę (porażka krytyczna).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from app.agent_tests.cases import host_for, load_cases
from app.agent_tests.harness import evaluate_case, summarize
from app.core.scope_guard import ScopeConfig
from app.explainer.providers import LLMProvider, OllamaProvider

HERE = Path(__file__).resolve().parent
SCOPE = HERE.parents[1] / "rules" / "scope.demo.yaml"


def provider(backend: str) -> LLMProvider | None:
    if backend == "template":
        return None
    return OllamaProvider(
        base_url=os.environ.get("OLLAMA_URL", "http://localhost:11434"),
        model=os.environ.get("LLM_MODEL", "qwen3-4b-q4km"),
        num_ctx=int(os.environ.get("LLM_NUM_CTX", "4096")),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=["ollama", "template"], default="ollama")
    parser.add_argument("--suite", choices=["quick", "full"], default="full")
    parser.add_argument("--out", type=Path, default=HERE.parent / "results" / "agent.json")
    args = parser.parse_args()

    base = load_cases(HERE / "cases.yaml")
    cases = load_cases(HERE / "cases.yaml", host_for(base.capability)).suite(args.suite)
    # Zakres demo-lab z denylistą (brama, skanery), jak w seed_demo.
    scope = ScopeConfig.from_file(SCOPE)
    llm = provider(args.backend)
    outcomes = [evaluate_case(case, llm, base.capability, scope) for case in cases]
    summary = summarize(outcomes)
    summary["backend"] = getattr(llm, "model", "template")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), "utf-8")

    lines = [
        f"### agent ({summary['backend']}, zestaw {args.suite})",
        "",
        f"Kod: **{summary['code_passed']}/{summary['cases']}** przypadków obronionych "
        f"(krytyczne). Model: {summary['model_passed']}/{summary['cases']} ataków odpartych.",
        "",
        "| Przypadek | Kategoria | Kod | Model | Werdykt |",
        "|---|---|---|---|---|",
    ]
    for item in summary["results"]:
        failed = [v["detail"] for v in item["verdicts"] if not v["passed"]]
        lines.append(
            "| {id} | {cat} | {code} | {model} | {why} |".format(
                id=item["case_id"],
                cat=item["category"],
                code="✅" if item["code_held"] else "❌",
                model="✅" if item["model_resisted"] else "⚠️",
                why="; ".join(failed).replace("|", "/")[:160],
            )
        )
    sys.stdout.write("\n".join(lines) + "\n")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
