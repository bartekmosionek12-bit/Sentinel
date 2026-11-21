"""Walidacja i podgląd celów skanowania bez wykonywania skanu."""

from __future__ import annotations

import csv
import io
import json
from ipaddress import ip_address, ip_network
from typing import Any

from app.core.scope_guard import Intrusiveness, ScopeGuard


def parse_targets(text: str, format: str) -> list[str]:
    if format == "manual":
        return [line.strip() for line in text.splitlines() if line.strip()]
    if format == "csv":
        return [str(row.get("target") or "").strip() for row in csv.DictReader(io.StringIO(text))]
    if format == "json":
        data: Any = json.loads(text)
        if isinstance(data, dict):
            data = data.get("targets")
        if not isinstance(data, list):
            raise ValueError("JSON musi zawierać listę celów")
        return [
            str(item.get("target", "") if isinstance(item, dict) else item).strip() for item in data
        ]
    raise ValueError("Nieznany format")


def validate_target(value: str, guard: ScopeGuard) -> tuple[str, str]:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 255:
        raise ValueError("Pusty albo za długi cel")
    try:
        address = ip_address(value)
    except ValueError:
        pass
    else:
        guard.authorize(
            str(address),
            tool="nmap",
            intrusiveness=Intrusiveness.LIGHT,
            rule_name="target_preview",
            dry_run=True,
        )
        return str(address), "ip"
    try:
        network = ip_network(value, strict=True)
    except ValueError:
        pass
    else:
        if not any(
            network.version == allowed.version and network.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in guard.config.allowed_cidrs
        ):
            raise ValueError("CIDR poza dozwolonym zakresem")
        if any(
            network.version == denied.version and network.subnet_of(denied)  # type: ignore[arg-type]
            for denied in guard.config.denied_cidrs
        ):
            raise ValueError("CIDR na denyliście")
        return str(network), "cidr"
    guard.authorize(
        value,
        tool="nmap",
        intrusiveness=Intrusiveness.LIGHT,
        rule_name="target_preview",
        dry_run=True,
    )
    return value, "domain"
