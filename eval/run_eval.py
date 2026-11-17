"""Ewaluacja modeli dla AI Explainera (Etap 3).

Uruchamia te same prompty, limity i walidator co aplikacja, na przypadkach z cases.yaml,
dla każdego modelu i każdego poziomu odbiorcy. Wynik: JSONL z odpowiedziami i RESULTS.md.

    cd backend
    uv run python ../eval/run_eval.py --ollama-url http://localhost:11434 \
        --model bielik-4.5b-q4km --model qwen3-4b-q4km --docker-container sentinel-ollama

Model i odpowiedzi nie decydują o niczym w systemie; ewaluacja wybiera tylko domyślny
LLM_MODEL na podstawie jakości tekstu.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import statistics
import subprocess
import sys
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from app.explainer.context import ExplainContext, ExplainerConfig, ProductFacts
from app.explainer.prompts import load_template
from app.explainer.providers import OllamaProvider, ProviderError, generate
from app.explainer.validator import looks_polish, validate
from app.models.ops import AUDIENCES

ROOT = Path(__file__).resolve().parent
RULES = ROOT.parent / "rules" / "explainer.yaml"
_DIACRITICS = set("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
_ENGLISH_LEFTOVERS = re.compile(r"\b(the|and|which|allows|attacker|vulnerability|in accordance)\b", re.I)


def load_cases(path: Path, config: ExplainerConfig) -> list[tuple[ExplainContext, dict[str, Any]]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = []
    for item in data["cases"]:
        vendor, product, title = item["product"]
        commands = tuple(item.get("commands") or config.verify_commands.get((vendor, product), ()))
        kev = item.get("kev") or {}
        due = kev.get("due")
        context = ExplainContext(
            cve_id=item["cve"],
            description=item["description"],
            cvss_score=float(item["cvss"]),
            epss=float(item["epss"]),
            in_kev=bool(kev),
            kev_due_date=due if isinstance(due, date) else (date.fromisoformat(due) if due else None),
            kev_required_action=kev.get("action"),
            has_public_exploit=bool(item.get("exploit")),
            products=(
                ProductFacts(
                    vendor,
                    product,
                    title,
                    tuple(item["ranges"]),
                    str(item["fixed"]) if item.get("fixed") else None,
                    commands,
                ),
            ),
        )
        cases.append((context, item))
    return cases


def expected(context: ExplainContext, item: dict[str, Any], audience: str) -> list[str]:
    if audience == "executive":
        items = ["aktualiz"]
    else:
        items = [context.cve_id]
        if context.fixed_versions:
            items.append(context.fixed_versions[0])
        if context.in_kev:
            items.append("KEV" if audience == "technical" else "atak")
        if audience == "operational" and context.kev_due_date:
            items.append(context.kev_due_date.isoformat())
    return items + list((item.get("expect") or {}).get(audience, []))


class MemorySampler:
    """Szczytowe zużycie pamięci (RSS) procesów kontenera z modelem, próbkowane co 2 s."""

    def __init__(self, container: str | None) -> None:
        self.container = container if container and shutil.which("docker") else None
        self.peak_mib = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _sample(self) -> float:
        """Suma VmRSS procesów kontenera (bez pamięci podręcznej plików, którą liczy docker stats)."""
        pids = subprocess.run(  # noqa: S603 - stała komenda, nazwa kontenera z argumentu
            ["docker", "top", str(self.container), "-o", "pid"],  # noqa: S607
            capture_output=True, text=True, timeout=15, check=False,
        ).stdout.split()[1:]
        total_kib = 0
        for pid in pids:
            try:
                status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
            except OSError:
                continue
            match = re.search(r"^VmRSS:\s+(\d+) kB", status, re.M)
            total_kib += int(match[1]) if match else 0
        return total_kib / 1024

    def _run(self) -> None:
        while not self._stop.wait(2):
            self.peak_mib = max(self.peak_mib, self._sample())

    def __enter__(self) -> MemorySampler:
        if self.container:
            self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()


def heuristics(text: str) -> dict[str, Any]:
    polish, _ = looks_polish(text)
    words = re.findall(r"[^\W\d_]+", text)
    return {
        "polish": polish,
        "diacritics_per_100_chars": round(100 * sum(c in _DIACRITICS for c in text) / max(len(text), 1), 2),
        "english_leftovers": len(_ENGLISH_LEFTOVERS.findall(text)),
        "words": len(words),
    }


def run_model(
    url: str, model: str, cases: list[tuple[ExplainContext, dict[str, Any]]], config: ExplainerConfig,
    out: Path, container: str | None,
) -> list[dict[str, Any]]:
    provider = OllamaProvider(base_url=url, model=model, num_ctx=4096, timeout=600)
    health = provider.health()
    if not health.available:
        raise SystemExit(f"{model}: {health.detail}")
    # Rozgrzewka: pierwsze wczytanie modelu nie wchodzi do pomiarów czasu.
    generate(provider, load_template("explain_executive").render("- Identyfikator: CVE-0000-0000"), max_tokens=8)
    rows: list[dict[str, Any]] = []
    with MemorySampler(container) as memory, out.open("a", encoding="utf-8") as sink:
        for index, (context, item) in enumerate(cases, start=1):
            for audience in AUDIENCES:
                limits = config.audiences[audience]
                prompt = load_template(f"explain_{audience}").render(context.facts_text())
                attempts, verdict, result = 0, None, None
                try:
                    while attempts < 2:
                        attempts += 1
                        result = generate(provider, prompt, max_tokens=limits.max_tokens)
                        verdict = validate(result.text, limits=limits, context=context, known_cves={context.cve_id})
                        if verdict.ok or not verdict.retryable:
                            break
                except ProviderError as error:
                    print(f"  {context.cve_id} {audience}: {error}", file=sys.stderr)
                    continue
                assert result is not None and verdict is not None
                wanted = expected(context, item, audience)
                text_lower = result.text.lower()
                stats = result.stats
                row = {
                    "model": model,
                    "cve": context.cve_id,
                    "audience": audience,
                    "attempts": attempts,
                    "passed_first": attempts == 1 and verdict.ok,
                    "passed": verdict.ok,
                    "problems": verdict.codes,
                    "fact_problems": [p.code for p in verdict.problems if not p.retryable],
                    "expected_found": sum(w.lower() in text_lower for w in wanted),
                    "expected_total": len(wanted),
                    "missing": [w for w in wanted if w.lower() not in text_lower],
                    "ttft_ms": result.first_token_ms,
                    "duration_ms": result.duration_ms,
                    "eval_tokens": stats.get("eval_count"),
                    "tokens_per_s": round(stats["eval_count"] / stats["eval_duration"] * 1e9, 2)
                    if stats.get("eval_count") and stats.get("eval_duration") else None,
                    "prompt_tokens": stats.get("prompt_eval_count"),
                    **heuristics(result.text),
                    "text": result.text,
                }
                rows.append(row)
                sink.write(json.dumps(row, ensure_ascii=False) + "\n")
                sink.flush()
                print(
                    f"[{model}] {index}/{len(cases)} {context.cve_id} {audience}: "
                    f"{'OK' if verdict.ok else ','.join(verdict.codes)} "
                    f"{result.duration_ms / 1000:.1f}s",
                    flush=True,
                )
    for row in rows:
        row["peak_ram_mib"] = round(memory.peak_mib) if memory.container else None
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def pct(values: list[bool]) -> float:
        return round(100 * sum(values) / len(values), 1) if values else 0.0

    by_audience = {
        a: {
            "passed_pct": pct([r["passed"] for r in rows if r["audience"] == a]),
            "passed_first_pct": pct([r["passed_first"] for r in rows if r["audience"] == a]),
        }
        for a in AUDIENCES
    }
    speeds = [r["tokens_per_s"] for r in rows if r["tokens_per_s"]]
    ttft = [r["ttft_ms"] for r in rows if r["ttft_ms"]]
    return {
        "answers": len(rows),
        "passed_pct": pct([r["passed"] for r in rows]),
        "passed_first_pct": pct([r["passed_first"] for r in rows]),
        "fact_rejections_pct": pct([bool(r["fact_problems"]) for r in rows]),
        "expected_pct": round(
            100 * sum(r["expected_found"] for r in rows) / max(sum(r["expected_total"] for r in rows), 1), 1
        ),
        "polish_pct": pct([r["polish"] for r in rows]),
        "english_leftovers": sum(r["english_leftovers"] for r in rows),
        "median_ttft_s": round(statistics.median(ttft) / 1000, 1) if ttft else None,
        "median_tokens_per_s": round(statistics.median(speeds), 1) if speeds else None,
        "median_duration_s": round(statistics.median(r["duration_ms"] for r in rows) / 1000, 1),
        "peak_ram_mib": rows[0].get("peak_ram_mib") if rows else None,
        "by_audience": by_audience,
        "problems": {
            code: sum(code in r["problems"] for r in rows)
            for code in sorted({c for r in rows for c in r["problems"]})
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--cases", type=Path, default=ROOT / "cases.yaml")
    parser.add_argument("--limit", type=int, default=0, help="tylko N pierwszych przypadków")
    parser.add_argument("--out", type=Path, default=ROOT / "results")
    parser.add_argument("--docker-container", default=None, help="kontener Ollamy do pomiaru RAM")
    args = parser.parse_args()

    config = ExplainerConfig.from_file(RULES)
    cases = load_cases(args.cases, config)
    if args.limit:
        cases = cases[: args.limit]
    args.out.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {}
    for model in args.model:
        raw = args.out / f"{model}.jsonl"
        raw.unlink(missing_ok=True)
        rows = run_model(args.ollama_url, model, cases, config, raw, args.docker_container)
        summary[model] = summarize(rows)
    (args.out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
