#!/usr/bin/env python3
"""Sprawdza przez API, czy seed_demo przeszedł całą ścieżkę krytyczną na demo-lab.

Użycie: python3 scripts/check_demo.py http://localhost:8080
Loguje się jak przeglądarka (Keycloak, PKCE, hasło i TOTP) kontami demo z pliku
data/demo-credentials.env, który tworzy scripts/seed_demo.sh. Tylko biblioteka standardowa.
Kod wyjścia 1, gdy którykolwiek warunek nie jest spełniony.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oidc_login import login  # noqa: E402

CREDENTIALS = Path(__file__).resolve().parent.parent / "data" / "demo-credentials.env"
TOKEN = {"value": ""}


def credentials() -> dict[str, str]:
    values = {}
    for line in CREDENTIALS.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def call(base: str, path: str, token: str) -> tuple[int, object]:
    request = urllib.request.Request(  # noqa: S310
        f"{base}/api{path}", headers={"Authorization": f"Bearer {token}"}
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        return error.code, None


def get(base: str, path: str) -> object:
    status, body = call(base, path, TOKEN["value"])
    if status != 200:
        raise SystemExit(f"BŁĄD GET /api{path}: HTTP {status}")
    return body


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8080"
    demo = credentials()
    TOKEN["value"] = login(
        base, "sentinel-admin", "admin", demo["DEMO_ADMIN_PASSWORD"], demo["DEMO_ADMIN_TOTP_SECRET"]
    )
    me = get(base, "/me")
    # Scenariusz demo 5: menedżer wchodzi do konsoli operacyjnej. Bez TOTP (nie jest adminem),
    # a API odmawia i zapisuje próbę w dzienniku audytu.
    manager_admin = login(base, "sentinel-admin", "manager", demo["DEMO_MANAGER_PASSWORD"])
    console_status, _ = call(base, "/console/admin", manager_admin)
    manager = login(base, "sentinel-dashboard", "manager", demo["DEMO_MANAGER_PASSWORD"])
    manager_assets_status, manager_assets = call(base, "/assets?limit=500", manager)
    manager_scan_status, _ = call(base, "/scan-actions", manager)
    denied = get(base, "/audit-log?action=access_denied&limit=50")
    findings = get(base, "/findings?status=active")["items"]  # type: ignore[index]
    stats = get(base, "/stats")
    assets = {a["name"]: a for a in get(base, "/assets?limit=500")["items"]}  # type: ignore[index]
    actions = get(base, "/scan-actions")
    audit = get(base, "/audit-log/verify")
    by_cve = {(f["vulnerability"]["cve_id"], f["asset"]["name"]): f for f in findings}
    web = by_cve.get(("CVE-2021-41773", "web-01"), {})
    explanation = get(base, f"/findings/{web['id']}/explanation?audience=technical") if web else {}
    llm = get(base, "/llm/status")
    explained = (
        isinstance(explanation, dict)
        and isinstance(llm, dict)
        and explanation.get("cve_id") == "CVE-2021-41773"
        and "Co to jest:" in explanation.get("text", "")
        and explanation.get("asset_context", "").startswith("Dotyczy: web-01")
        and (explanation.get("source") == "template" or bool(llm.get("available")))
    )

    manager_names = {a["name"] for a in manager_assets["items"]} if manager_assets else set()  # type: ignore[index]
    checks = {
        "admin zalogowany przez Keycloak z TOTP (MFA w tokenie)": isinstance(me, dict)
        and me.get("mfa") is True
        and "admin" in me.get("roles", []),
        "menedżer nie wchodzi do konsoli operacyjnej (403)": console_status == 403,
        "odmowa dla menedżera zapisana w dzienniku audytu": any(
            e["actor"] == "user:manager" and e["inputs"].get("permission") == "console:admin"
            for e in denied["items"]  # type: ignore[index]
        ),
        "menedżer widzi inwentarz bez adresów IP": manager_assets_status == 200
        and "172.30.99.14" not in manager_names
        and "[adres ukryty]" in manager_names,
        "menedżer nie ma dostępu do skanów (403)": manager_scan_status == 403,
        "CVE-2021-41773 na web-01 jest krytyczne": by_cve.get(("CVE-2021-41773", "web-01"), {}).get(
            "risk_level"
        )
        == "krytyczny",
        "najwyższe ryzyko jest pierwsze na liście": bool(findings)
        and findings[0]["risk_score"] == max(f["risk_score"] for f in findings),
        "nginx dopasowany przez alias (CVE-2021-23017 na proxy-01)": ("CVE-2021-23017", "proxy-01")
        in by_cve,
        "pakiet z Debiana czeka w kolejce weryfikacji, bez findingów": stats["review_queue"] == 1  # type: ignore[index]
        and not any(asset == "legacy-01" for _, asset in by_cve),
        "host spoza inwentarza oznaczony jako shadow IT": assets.get("172.30.99.14", {}).get(
            "status"
        )
        == "shadow",
        "zasób, który nie odpowiada, oznaczony jako missing": assets.get("old-db-01", {}).get(
            "status"
        )
        == "missing",
        "skan L2 wykonany ze zgodą seed_demo": any(
            a["intrusiveness"] == 2
            and a["status"] == "done"
            and a["approval_source"] == "seed_demo"
            for a in actions  # type: ignore[union-attr]
        ),
        "żadna akcja nie dotknęła adresu spoza demo-lab": all(
            a["target"].startswith("172.30.99.")
            for a in actions  # type: ignore[union-attr]
        ),
        "feedy wczytane w trybie offline": all(
            f["status"] == "ok" and f["mode"] == "offline"
            for f in stats["feeds"]  # type: ignore[index]
        ),
        "powiadomienie o KEV na zasobie z internetu": stats["notifications_today"] >= 1,  # type: ignore[index]
        "wyjaśnienie dostępne także bez modelu (szablon z faktami z bazy)": explained,
        "łańcuch dziennika audytu jest spójny": audit["ok"] is True,  # type: ignore[index]
    }
    failed = [name for name, ok in checks.items() if not ok]
    for name, ok in checks.items():
        sys.stdout.write(f"{'OK  ' if ok else 'BŁĄD'} {name}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
