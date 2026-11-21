#!/usr/bin/env python3
"""Tworzy lokalny .env z losowymi hasłami bez wypisywania ich do konsoli."""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_KEYS = {
    "POSTGRES_PASSWORD", "APP_DB_PASSWORD", "KEYCLOAK_DB_PASSWORD",
    "HARNESS_DB_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD", "AGENT_CLIENT_SECRET",
    "KILLSWITCH_CLIENT_SECRET",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true", help="świadomie włącz izolowany demo-lab")
    args = parser.parse_args()
    destination = ROOT / ".env"
    if destination.exists():
        print(".env już istnieje; pozostawiono bez zmian")
        return
    lines = []
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            name, _, value = line.partition("=")
            if name in SECRET_KEYS:
                line = f"{name}={secrets.token_hex(32)}"
            elif name == "DEMO_MODE" and args.demo:
                line = "DEMO_MODE=true"
        lines.append(line)
    lines.extend([
        f"DD_DB_PASSWORD={secrets.token_hex(32)}",
        f"DD_SECRET_KEY={secrets.token_hex(48)}",
        f"DD_CREDENTIAL_AES_256_KEY={secrets.token_hex(16)}",
    ])
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    destination.chmod(0o600)
    print("Utworzono .env z lokalnymi hasłami")


if __name__ == "__main__":
    main()
