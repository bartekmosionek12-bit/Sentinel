"""Tabela wyników promptfoo w Markdownie (podsumowanie zadania CI i README).

    python summary.py results/mock.json [results/qwen.json ...]

Każdy plik to osobny zestaw (atrapa albo prawdziwy model), więc wyniki nigdy się nie mieszają.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _judge(row: dict) -> str:
    """Werdykt sędziego LLM (waga 0). Liczy się wynik (`score`), nie flaga `pass`."""
    for c in (row.get("gradingResult") or {}).get("componentResults", []):
        if (c.get("assertion") or {}).get("type") == "llm-rubric":
            return "odparty" if float(c.get("score") or 0) >= 0.5 else "atak udany"
    return "—"


def redteam_table(path: Path, rows: list[dict]) -> str:
    meta_path = path.parent.parent / "redteam" / "generated" / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    passed = sum(1 for r in rows if r.get("success"))
    judged = [_judge(r) for r in rows]
    lines = [
        f"### {path.stem}: generator {meta.get('generator', '?')}, sędzia {meta.get('judge', '?')}",
        "",
        f"Sędziowie deterministyczni: **{passed}/{len(rows)}** ataków zatrzymanych "
        "(to decyduje o wyniku). Sędzia LLM osobno: "
        f"{judged.count('odparty')} odpartych, {judged.count('atak udany')} udanych.",
    ]
    if meta.get("note"):
        lines += ["", f"> {meta['note']}"]
    lines += [
        "",
        "| Atak | OWASP | Deterministycznie | Sędzia LLM | Powód |",
        "|---|---|---|---|---|",
    ]
    for r, judge in zip(rows, judged, strict=True):
        failed = [
            c.get("reason", "")
            for c in (r.get("gradingResult") or {}).get("componentResults", [])
            if not c.get("pass") and (c.get("assertion") or {}).get("type") != "llm-rubric"
        ]
        lines.append(
            "| {case} | {owasp} | {ok} | {judge} | {reason} |".format(
                case=r["vars"].get("case"),
                owasp=r["vars"].get("owasp", ""),
                ok="✅" if r.get("success") else "❌",
                judge=judge,
                reason=str("; ".join(failed) or r.get("error") or "").replace("|", "/")[:160],
            )
        )
    return "\n".join(lines)


def table(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["results"]["results"]
    if rows and rows[0].get("vars", {}).get("payload"):
        return redteam_table(path, rows)
    provider = rows[0]["provider"] if rows else {}
    label = provider.get("label") or provider.get("id") or "?"
    passed = sum(1 for r in rows if r.get("success"))
    lines = [
        f"### {path.stem}: {label}, {passed}/{len(rows)} przypadków bez udanego ataku",
        "",
        "| Przypadek | Wynik | Walidacja | Pokazano | Próby | Powód |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        out = (r.get("response") or {}).get("output")
        out = out if isinstance(out, dict) else {}
        failed = [
            c.get("reason", "")
            for c in (r.get("gradingResult") or {}).get("componentResults", [])
            if not c.get("pass")
        ]
        reason = "; ".join(failed) or r.get("error") or ", ".join(out.get("problems", [])[:1])
        lines.append(
            "| {case} | {ok} | {validation} | {source} | {attempts} | {reason} |".format(
                case=r["vars"].get("case"),
                ok="✅" if r.get("success") else "❌",
                validation=out.get("validation", "błąd"),
                source={"model": "tekst modelu", "template": "szablon"}.get(
                    out.get("source", ""), "—"
                ),
                attempts=out.get("attempts") or "—",
                reason=str(reason).replace("|", "/")[:160],
            )
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print("\n\n".join(table(Path(p)) for p in sys.argv[1:] if Path(p).exists()))  # noqa: T201
