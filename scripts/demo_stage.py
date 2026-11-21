#!/usr/bin/env python3
"""Przygotowanie stanu do nagrania filmu demo (moduł 22), wyłącznie przez API.

    python3 scripts/demo_stage.py http://localhost:8080

Po scripts/seed_demo.sh sprawdza i w razie potrzeby uzupełnia to, co pokazują sceny:
- test bezpieczeństwa agenta zaliczony (scena „odporność”), w razie braku zleca szybki test,
- zadanie agenta z certyfikatem SSH (scena „bezpieczny agent”): tworzy je jako admin, czeka
  na plan, zatwierdza z powodem i czeka na lease. Zgoda idzie tą samą ścieżką co w konsoli
  (RBAC, scope_guard, audyt); skrypt nie omija niczego,
- scena zero-day wstrzykuje KEV sama w trakcie nagrania, więc tu tylko ostrzeżenie, gdy
  raport zero-day już jest w skrzynce (wtedy baner nie pojawi się „na żywo”).

Loguje się jak przeglądarka (oidc_login.py) kontami z data/demo-credentials.env.
Kod wyjścia 1, gdy stanu nie da się przygotować. Tylko biblioteka standardowa.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_demo import call, credentials  # noqa: E402
from oidc_login import login  # noqa: E402

COMMAND = "Zbierz listę zainstalowanego oprogramowania z app-01 przez SSH"
REASON = "Nagranie filmu demo: odczyt pakietów app-01 przez SSH w sieci demo-lab"


def wait(what: str, check: object, timeout: float, every: float = 3.0) -> object:
    """Woła `check()` do skutku (wartość różna od None) albo do upływu czasu."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()  # type: ignore[operator]
        if value is not None:
            return value
        time.sleep(every)
    raise SystemExit(f"BŁĄD: {what}: brak w ciągu {timeout:.0f} s")


def ensure_agent_test(base: str, token: str) -> None:
    def passed() -> object:
        _, status = call(base, "/agent/status", token)
        last = (status or {}).get("last_test") or {} if isinstance(status, dict) else {}
        return True if last.get("passed") else None

    if passed():
        print("OK  test agenta zaliczony")
        return
    code, _ = call(base, "/agent/tests", token, {"suite": "quick"})
    if code != 202:
        raise SystemExit(f"BŁĄD: zlecenie testu agenta: HTTP {code}")
    print("..  zleciłem szybki test agenta, czekam na wynik")
    wait("zaliczony test agenta", passed, timeout=600, every=10)
    print("OK  test agenta zaliczony")


def ensure_lease(base: str, token: str) -> None:
    def leases() -> list[dict[str, object]]:
        _, rows = call(base, "/agent/leases", token)
        if not isinstance(rows, list):
            return []
        return [r for r in rows if isinstance(r, dict) and r.get("kind") == "ssh_cert"]

    if leases():
        print("OK  jest lease certyfikatu SSH z wcześniejszego zadania")
        return
    code, task = call(base, "/agent/tasks", token, {"command": COMMAND})
    if code != 202 or not isinstance(task, dict):
        raise SystemExit(f"BŁĄD: nowe zadanie agenta: HTTP {code}")
    task_id = task["id"]
    print(f"..  zadanie agenta {task_id}, czekam na plan")

    def planned() -> object:
        _, row = call(base, f"/agent/tasks/{task_id}", token)
        state = row.get("status") if isinstance(row, dict) else None
        if state in {"failed", "rejected"}:
            raise SystemExit(f"BŁĄD: zadanie agenta skończyło się stanem {state}")
        return row if state == "awaiting_approval" else None

    wait("plan zadania agenta", planned, timeout=180)
    code, _ = call(base, f"/agent/tasks/{task_id}/approve", token, {"reason": REASON})
    if code != 202:
        raise SystemExit(f"BŁĄD: zatwierdzenie zadania: HTTP {code}")
    print("..  zatwierdzone, czekam na certyfikat SSH")
    wait("lease certyfikatu SSH", lambda: leases() or None, timeout=180)
    print("OK  lease certyfikatu SSH wydany (15 min, bez sekretu w API)")


def warn_zero_day(base: str, manager: str) -> None:
    _, inbox = call(base, "/inbox", manager)
    items = inbox.get("items", []) if isinstance(inbox, dict) else []
    if any(item.get("kind") == "zero_day" for item in items):
        print(
            "UWAGA: raport zero-day już jest w skrzynce. Scena „zero-day” pokaże go od razu,"
            " bez przyjścia na żywo. Do czystego nagrania: świeży seed_demo.sh."
        )
    else:
        print("OK  brak raportu zero-day: scena wstrzyknie KEV na żywo")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    base = sys.argv[1].rstrip("/")
    demo = credentials()
    admin = login(
        base,
        "sentinel-admin",
        "admin",
        demo["DEMO_ADMIN_PASSWORD"],
        demo["DEMO_ADMIN_TOTP_SECRET"],
    )
    manager = login(base, "sentinel-dashboard", "manager", demo["DEMO_MANAGER_PASSWORD"])
    ensure_agent_test(base, admin)
    ensure_lease(base, admin)
    warn_zero_day(base, manager)
    print("Stan gotowy do nagrania: ./scripts/record_demo.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
