"""Tabela wyników promptfoo w Markdownie (podsumowanie zadania CI i README).

    python summary.py results/mock.json [results/qwen.json ...]

Każdy plik to osobny zestaw (atrapa albo prawdziwy model), więc wyniki nigdy się nie mieszają.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def table(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data["results"]["results"]
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
