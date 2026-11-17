#!/usr/bin/env python3
"""Sprawdza przez API, czy seed_demo przeszedł całą ścieżkę krytyczną na demo-lab.

Użycie: python3 scripts/check_demo.py http://localhost:8080
Tylko biblioteka standardowa. Kod wyjścia 1, gdy którykolwiek warunek nie jest spełniony.
"""

from __future__ import annotations

import json
import sys
import urllib.request


def get(base: str, path: str) -> object:
    with urllib.request.urlopen(f"{base}/api{path}", timeout=15) as response:  # noqa: S310
        return json.load(response)


def main() -> int:
    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8080"
    findings = get(base, "/findings?status=active")["items"]  # type: ignore[index]
    stats = get(base, "/stats")
    assets = {a["name"]: a for a in get(base, "/assets?limit=500")["items"]}  # type: ignore[index]
    actions = get(base, "/scan-actions")
    audit = get(base, "/audit-log/verify")
    by_cve = {(f["vulnerability"]["cve_id"], f["asset"]["name"]): f for f in findings}

    checks = {
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
        "host spoza inwentarza oznaczony jako shadow IT": assets.get("172.30.99.14", {}).get("status")
        == "shadow",
        "zasób, który nie odpowiada, oznaczony jako missing": assets.get("old-db-01", {}).get("status")
        == "missing",
        "skan L2 wykonany ze zgodą seed_demo": any(
            a["intrusiveness"] == 2 and a["status"] == "done" and a["approval_source"] == "seed_demo"
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
        "łańcuch dziennika audytu jest spójny": audit["ok"] is True,  # type: ignore[index]
    }
    failed = [name for name, ok in checks.items() if not ok]
    for name, ok in checks.items():
        sys.stdout.write(f"{'OK  ' if ok else 'BŁĄD'} {name}\n")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
