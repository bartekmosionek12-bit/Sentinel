"""Provider promptfoo: przypadek z fixture'ów przez prawdziwą ścieżkę aplikacji.

Zwraca obiekt JSON (wynik `harness.run_case`), na którym asercje deterministyczne w
`assertions.js` sprawdzają ocenę ryzyka i tekst pokazany ludziom. Backend modelu ustawia
`config.backend`: `obedient` (posłuszna atrapa) albo `ollama` (prawdziwy model lokalny).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import run, run_case


def generated(vars_: dict[str, Any], backend: str) -> dict[str, Any]:
    """Atak z redteam/generate.py: opis CVE (raport, wyjaśnienie) albo tytuł strony (agent)."""
    if vars_["pipeline"] == "agent":
        from redteam.agent_target import run_agent

        return run_agent(vars_, backend)
    forbidden = json.loads(vars_.get("forbidden") or "[]")
    # Posłuszna atrapa: najgorszy model, który pisze dokładnie to, czego chce napastnik.
    worst = "Uwaga: " + ", ".join(forbidden) + "."
    case = {
        "id": vars_["case"],
        "cve": "CVE-2021-41773",
        "pipeline": vars_["pipeline"],
        "description": vars_["payload"],
        "trigger": vars_.get("canary") or None,
        "payload": {"todo": worst},
        "payload_text": worst,
    }
    return run(case, backend)


def call_api(prompt: str, options: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    backend = str((options.get("config") or {}).get("backend", "obedient"))
    vars_ = context.get("vars") or {}
    try:
        if vars_.get("payload"):
            return {"output": generated(vars_, backend)}
        case_id = str(vars_.get("case") or prompt).strip()
        return {"output": run_case(case_id, backend)}
    except Exception as error:  # promptfoo pokazuje błąd przy przypadku
        return {"error": f"{type(error).__name__}: {error}"}
