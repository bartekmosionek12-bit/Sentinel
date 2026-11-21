#!/usr/bin/env python3
"""Przygotowanie stanu do nagrania filmu demo, wyłącznie przez API (i docker compose).

    python3 scripts/demo_stage.py http://localhost:8080 demo/out/stage.json

Trzy prawdziwe przebiegi discovery sieci demo-lab ze zmianą między nimi:
  run1: wszystkie usługi demo-lab poza lab-ssh,
  run2: lab-ssh włączony, lab-cache wyłączony (nowy host i host, który zniknął),
  run3: lab-cache znowu działa (odpowiada, nie, odpowiada, więc dostaje stan „niestabilny”).
lab-poisoned (strona z próbą prompt injection do testów agenta) jest na czas nagrania
wyłączony, żeby nie trafił do kadru; na końcu wszystko wraca do stanu sprzed skryptu.
Skany idą tą samą ścieżką co z konsoli: RBAC, scope_guard, limity tempa i audyt.
Identyfikatory przebiegów zapisuje do pliku JSON dla nagrywarki ({run1} {run2} {run3}).
Tylko biblioteka standardowa.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_demo import call, credentials
from oidc_login import login

LAB = "172.30.99.0/24"


def compose(*args: str) -> None:
    subprocess.run(["docker", "compose", *args], check=True)


_TOKEN: dict[str, object] = {}


def token(base: str) -> str:
    """Token admina, odświeżany co 4 minuty (kod TOTP wolno użyć tylko raz na 30 s)."""
    if time.monotonic() - float(_TOKEN.get("at", -1e9)) > 240:  # type: ignore[arg-type]
        demo = credentials()
        _TOKEN["value"] = login(
            base,
            "sentinel-admin",
            "admin",
            demo["DEMO_ADMIN_PASSWORD"],
            demo["DEMO_ADMIN_TOTP_SECRET"],
        )
        _TOKEN["at"] = time.monotonic()
    return str(_TOKEN["value"])


def run(base: str, name: str) -> str:
    code, body = call(
        base, "/discovery/runs", token(base), {"items": [LAB], "name": name, "settings": {}}
    )
    if code != 202 or not isinstance(body, dict):
        raise SystemExit(f"BŁĄD: start przebiegu {name!r}: HTTP {code}")
    run_id = str(body["id"])
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        time.sleep(5)
        code, state = call(base, f"/discovery/runs/{run_id}", token(base))
        status = state.get("status") if isinstance(state, dict) else None
        if status == "done":
            print(f"OK  {name}: {state['hosts_up']} hostów, {state['duration_seconds']} s")
            return run_id
        if status in ("failed", "stopped"):
            raise SystemExit(f"BŁĄD: przebieg {name!r} zakończony stanem {status}")
    raise SystemExit(f"BŁĄD: przebieg {name!r} nie skończył się w 15 minut")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    base, out = sys.argv[1].rstrip("/"), Path(sys.argv[2])
    try:
        compose("stop", "lab-poisoned", "lab-ssh")
        run1 = run(base, "Kampus, poniedziałek")
        compose("start", "lab-ssh")
        compose("stop", "lab-cache")
        time.sleep(5)
        run2 = run(base, "Kampus, wtorek")
        compose("start", "lab-cache")
        time.sleep(5)
        run3 = run(base, "Kampus, środa")
    finally:
        compose("start", "lab-ssh", "lab-cache")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"run1": run1, "run2": run2, "run3": run3}), encoding="utf-8")
    print(f"Stan gotowy: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
