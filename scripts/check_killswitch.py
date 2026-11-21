#!/usr/bin/env python3
"""Kill switch na żywo (CI, demo-lab): sprawdza wszystkie trzy skutki na prawdziwych usługach.

Użycie (po seed_demo.sh, jako ostatni krok, bo wyłącza agenta):
    python3 scripts/check_killswitch.py http://localhost:8080

1. Keycloak: przed kill switchem konto agenta dostaje token (client credentials), po nim nie.
2. OpenBao: token z logowania AppRole serwera MCP (wydany przed kill switchem) przestaje działać
   (`lookup-self` → 403). Token nie opuszcza kontenera `mcp-scanner`.
3. mcp-scanner: strażnik potwierdza zatrzymanie (`scanner_stopped_at`), a krok, który trwał w
   chwili wyłączenia (pełny skan portów), kończy się jako przerwany przez kill switch.

Tylko biblioteka standardowa i `docker compose`. Kod wyjścia 1, gdy którykolwiek warunek nie
jest spełniony. Ten sam przepływ bez sieci: backend/tests/test_killswitch.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_demo import credentials, report
from oidc_login import login

ROOT = Path(__file__).resolve().parent.parent
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
HOST = "172.30.99.12"

BAO_LOGIN = """
import json, pathlib, urllib.request as u
o = u.build_opener(u.ProxyHandler({}))
creds = json.loads(pathlib.Path("/run/openbao/approle.json").read_text())
req = u.Request("http://openbao:8200/v1/auth/approle/login", data=json.dumps(creds).encode(),
                headers={"Content-Type": "application/json"})
token = json.loads(o.open(req, timeout=10).read())["auth"]["client_token"]
pathlib.Path("/tmp/killswitch-check-token").write_text(token)
print("ok")
"""
BAO_LOOKUP = """
import pathlib, urllib.error, urllib.request as u
o = u.build_opener(u.ProxyHandler({}))
token = pathlib.Path("/tmp/killswitch-check-token").read_text()
req = u.Request("http://openbao:8200/v1/auth/token/lookup-self", headers={"X-Vault-Token": token})
try:
    print(o.open(req, timeout=10).status)
except urllib.error.HTTPError as error:
    print(error.code)
"""


def env_value(name: str) -> str:
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip()
    return ""


def agent_token_status(base: str) -> int:
    data = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode()
    request = urllib.request.Request(  # noqa: S310
        f"{base}/auth/realms/sentinel/protocol/openid-connect/token", data=data
    )
    secret = env_value("AGENT_CLIENT_SECRET")
    import base64

    basic = base64.b64encode(f"sentinel-agent:{secret}".encode()).decode()
    request.add_header("Authorization", f"Basic {basic}")
    try:
        with OPENER.open(request, timeout=15) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)


def in_scanner(code: str) -> str:
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "mcp-scanner", "python", "-"],  # noqa: S607
        input=code,
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    return (
        (result.stdout or result.stderr).strip().splitlines()[-1]
        if result.stdout or result.stderr
        else ""
    )


def api(
    base: str, token: str, method: str, path: str, body: object | None = None
) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with OPENER.open(request, timeout=30) as response:
            raw = response.read()
            return int(response.status), json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        return int(error.code), None


def wait_for(predicate, timeout: float, interval: float = 0.5):  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8080"
    demo = credentials()
    admin = login(
        base, "sentinel-admin", "admin", demo["DEMO_ADMIN_PASSWORD"], demo["DEMO_ADMIN_TOTP_SECRET"]
    )
    before_keycloak = agent_token_status(base)
    bao_login = in_scanner(BAO_LOGIN)

    # Krok, który trwa w chwili wyłączenia: pełny skan portów hosta demo-lab.
    _, task = api(base, admin, "POST", "/agent/tasks", {"command": f"Pełny skan portów {HOST}"})
    task_id = task["id"] if isinstance(task, dict) else ""

    def task_state() -> dict | None:  # type: ignore[type-arg]
        status, body = api(base, admin, "GET", f"/agent/tasks/{task_id}")
        return body if status == 200 and isinstance(body, dict) else None

    planned = wait_for(
        lambda: (t := task_state()) and t["status"] == "awaiting_approval" and t, 120
    )
    if planned:
        api(base, admin, "POST", f"/agent/tasks/{task_id}/approve", {"reason": "test kill switcha"})
    running = wait_for(
        lambda: (t := task_state()) and any(s["status"] == "running" for s in t["steps"]) and t,
        60,
        0.2,
    )

    kill_status, killed = api(
        base, admin, "POST", "/agent/kill", {"reason": "CI: test kill switcha na żywo"}
    )
    effects = (
        {e["name"]: e for e in (killed or {}).get("effects", [])}
        if isinstance(killed, dict)
        else {}
    )
    after_keycloak = agent_token_status(base)
    bao_after = in_scanner(BAO_LOOKUP)
    status_body = wait_for(
        lambda: (
            (s := api(base, admin, "GET", "/agent/status")[1])
            and isinstance(s, dict)
            and s.get("scanner_stopped_at")
            and s
        ),
        15,
    )
    final = wait_for(
        lambda: (t := task_state()) and all(s["status"] != "running" for s in t["steps"]) and t, 30
    )
    steps = final["steps"] if isinstance(final, dict) else []
    interrupted = [
        s for s in steps if s.get("decision") == "agent_killed" and s["status"] == "failed"
    ]

    checks = {
        "kill switch przyjęty przez API": kill_status == 200,
        "Keycloak: przed wyłączeniem konto agenta dostaje token": before_keycloak == 200,
        "Keycloak: po wyłączeniu klient agenta nie dostaje tokenu": after_keycloak in (400, 401),
        "Keycloak: skutek zapisany jako wykonany": bool(effects.get("keycloak", {}).get("ok")),
        "OpenBao: token mcp-scanner wydany przed wyłączeniem": bao_login == "ok",
        "OpenBao: ten token po kill switchu jest odwołany (403)": bao_after == "403",
        "OpenBao: skutek zapisany jako wykonany": bool(effects.get("openbao", {}).get("ok")),
        "mcp-scanner potwierdził zatrzymanie": bool(status_body),
        "mcp-scanner: krok trwający w chwili wyłączenia został przerwany": bool(running)
        and bool(interrupted),
    }
    if not running:
        sys.stdout.write(
            "UWAGA: nie złapano trwającego kroku (skan skończył się przed kill switchem)\n"
        )
    return report(checks)


if __name__ == "__main__":
    raise SystemExit(main())
