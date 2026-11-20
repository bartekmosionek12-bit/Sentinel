"""Provider promptfoo: przypadek z fixture'ów przez prawdziwą ścieżkę aplikacji.

Zwraca obiekt JSON (wynik `harness.run_case`), na którym asercje deterministyczne w
`assertions.js` sprawdzają ocenę ryzyka i tekst pokazany ludziom. Backend modelu ustawia
`config.backend`: `obedient` (posłuszna atrapa) albo `ollama` (prawdziwy model lokalny).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import run_case


def call_api(prompt: str, options: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    backend = str((options.get("config") or {}).get("backend", "obedient"))
    case_id = str((context.get("vars") or {}).get("case") or prompt).strip()
    try:
        return {"output": run_case(case_id, backend)}
    except Exception as error:  # promptfoo pokazuje błąd przy przypadku
        return {"error": f"{type(error).__name__}: {error}"}
