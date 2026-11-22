"""Grupowanie podatności warstwy 1 i ich postać dla DefectDojo.

Grupa = jeden rodzaj problemu (`group_key`, np. `tls_old_protocol` albo
`outdated_software:openssh`) ze wszystkimi punktami końcowymi, na których wystąpił.
Do DefectDojo idzie jeden finding na grupę z listą endpointów, a nie setki kopii.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from datetime import date
from typing import Any

from app.models import RedteamFinding, RedteamRun
from app.redteam.engine import SEVERITY_RANK

DOJO_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def group_findings(rows: Iterable[RedteamFinding]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        group = groups.setdefault(
            row.group_key,
            {
                "group_key": row.group_key,
                "check": row.check_id,
                "title": row.title,
                "severity": row.severity,
                "category": row.category,
                "count": 0,
                "hosts": [],
            },
        )
        if SEVERITY_RANK.get(row.severity, 9) < SEVERITY_RANK.get(group["severity"], 9):
            group["severity"] = row.severity
        group["count"] += 1
        group["hosts"].append(
            {
                "ip": row.ip,
                "port": row.port,
                "protocol": row.protocol,
                "service": row.service,
                "evidence": list(row.evidence),
            }
        )
    for group in groups.values():
        group["hosts"].sort(key=lambda h: (h["ip"], h["port"] or 0))
        group["unique_hosts"] = len({h["ip"] for h in group["hosts"]})
    return sorted(
        groups.values(),
        key=lambda g: (SEVERITY_RANK.get(g["severity"], 9), -g["count"], g["title"]),
    )


def _endpoints_hash(hosts: Sequence[dict[str, Any]]) -> str:
    text = "|".join(sorted(f"{h['ip']}:{h['port']}/{h['protocol']}" for h in hosts))
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def dojo_findings(
    run: RedteamRun,
    groups: Sequence[dict[str, Any]],
    mitigations: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Jeden finding na grupę. Ten sam zestaw punktów końcowych = ten sam identyfikator."""
    out: list[dict[str, Any]] = []
    for group in groups:
        lines = [
            f"- {h['ip']}:{h['port']}/{h['protocol']} {h['service']}: "
            + "; ".join(h["evidence"])[:300]
            for h in group["hosts"]
        ]
        finding: dict[str, Any] = {
            "title": f"{group['title']} ({group['unique_hosts']} hostów)",
            "severity": DOJO_SEVERITY.get(group["severity"], "Info"),
            "description": (
                f"Warstwa 1 Sentinel ASI (deterministyczny skan, przebieg {run.id}).\n"
                f"Kategoria: {group['category']}. Wystąpienia: {group['count']}.\n\n"
                + "\n".join(lines)
            ),
            "unique_id_from_tool": (
                f"redteam:{group['group_key']}:{_endpoints_hash(group['hosts'])}"
            ),
            "vuln_id_from_tool": f"sentinel-redteam:{group['group_key']}",
            "endpoints": [
                {"host": h["ip"], "port": h["port"], "protocol": h["protocol"]}
                for h in group["hosts"]
                if h["port"]
            ],
            "date": date.today().isoformat(),
        }
        if mitigations and group["group_key"] in mitigations:
            finding["mitigation"] = mitigations[group["group_key"]]
        out.append(finding)
    return out
