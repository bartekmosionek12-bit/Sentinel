"""Porównanie przebiegów, stan hosta i warstwa nadpisań (deterministyczne, bez modelu)."""

from __future__ import annotations

import ipaddress
import itertools
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DiscoveryRun, Observation, ObservationOverride

# Pola, które człowiek może nadpisać. Kolejny skan ich nie kasuje (inna tabela, klucz = IP).
OVERRIDE_FIELDS = ("hostname", "note", "tags", "hidden_flags", "criticality", "status")
STATE_LABELS = {
    "active": "aktywny",
    "unstable": "niestabilny",
    "unconfirmed": "niepotwierdzony",
    "inactive": "nieaktywny",
}


def _covers(targets: list[str], ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for target in targets:
        try:
            if address in ipaddress.ip_network(target.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def host_states(
    session: Session, *, inactive_after: int = 3, window: int = 5
) -> dict[str, dict[str, Any]]:
    """Stan każdego znanego hosta z ostatnich przebiegów, które obejmowały jego adres.

    * aktywny: odpowiedział w ostatnim przebiegu i w oknie nie ma przeplotu,
    * niestabilny: w oknie odpowiedzi przeplatają się z ich brakiem (np. tak, nie, tak),
    * niepotwierdzony: nie odpowiedział ostatnio, ale braków jest mniej niż N,
    * nieaktywny: N kolejnych przebiegów bez odpowiedzi (N = `inactive_after`).
    """
    runs = list(
        session.scalars(
            select(DiscoveryRun)
            .where(DiscoveryRun.status.in_(("done", "stopped")))
            .order_by(DiscoveryRun.created_at.desc())
            .limit(50)
        )
    )
    seen: dict[uuid.UUID, set[str]] = {run.id: set() for run in runs}
    for run_id, ip in session.execute(
        select(Observation.run_id, Observation.ip).where(Observation.run_id.in_(seen))
    ):
        seen[run_id].add(ip)
    all_ips = set().union(*seen.values()) if seen else set()
    out: dict[str, dict[str, Any]] = {}
    for ip in all_ips:
        history: list[bool] = []
        for run in runs:
            if ip in seen[run.id] or _covers(run.targets, ip):
                history.append(ip in seen[run.id])
            if len(history) >= max(window, inactive_after):
                break
        recent = history[:window]
        misses = 0
        for answered in history:
            if answered:
                break
            misses += 1
        flips = sum(1 for a, b in itertools.pairwise(recent) if a != b)
        if misses >= inactive_after:
            state = "inactive"
        elif history and history[0] and flips >= 2:
            state = "unstable"
        elif history and not history[0]:
            state = "unstable" if flips >= 2 else "unconfirmed"
        else:
            state = "active"
        out[ip] = {
            "state": state,
            "label": STATE_LABELS[state],
            "history": history[:window],
            "misses": misses,
        }
    return out


def overrides(session: Session) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in session.scalars(select(ObservationOverride)):
        result.setdefault(row.ip, {})[row.field] = {
            "value": row.value,
            "by": row.updated_by,
            "at": row.updated_at.isoformat(),
        }
    return result


def present(
    observation: Observation,
    edits: dict[str, Any] | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Obserwacja ze skanu scalona z nadpisaniami (przy odczycie, skan niczego nie kasuje)."""
    edits = edits or {}
    hidden = set((edits.get("hidden_flags") or {}).get("value") or [])
    flags = [f for f in observation.flags if f.get("kind") not in hidden]
    data: dict[str, Any] = {
        "ip": observation.ip,
        "hostname": observation.hostname,
        "services": observation.services,
        "http": observation.http,
        "flags": flags,
        "technologies": sorted({t for h in observation.http for t in h.get("technologies", [])}),
        "note": None,
        "tags": [],
        "criticality": None,
        "status": None,
        "edited": sorted(edits),
        "edits": edits,
        "state": state,
    }
    for name in ("hostname", "note", "tags", "criticality", "status"):
        if name in edits:
            data[name] = edits[name]["value"]
    return data


def _signature(observation: Observation) -> dict[str, Any]:
    services = {
        f"{s['port']}/{s.get('protocol', 'tcp')}": " ".join(
            p for p in (s.get("name"), s.get("product"), s.get("version")) if p
        )
        for s in observation.services
    }
    technologies = sorted({t for h in observation.http for t in h.get("technologies", [])})
    headers = {
        f"{h['port']}:{k}": v
        for h in observation.http
        for k, v in (h.get("headers") or {}).items()
        if k in {"server", "x-powered-by", "x-generator", "x-aspnet-version"}
    }
    titles = {str(h["port"]): h.get("title") or "" for h in observation.http}
    flags = sorted(f["kind"] for f in observation.flags)
    return {
        "hostname": observation.hostname,
        "services": services,
        "technologies": technologies,
        "headers": headers,
        "titles": titles,
        "flags": flags,
    }


def _dict_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    added = {k: new[k] for k in new.keys() - old.keys()}
    removed = {k: old[k] for k in old.keys() - new.keys()}
    changed = {k: [old[k], new[k]] for k in old.keys() & new.keys() if old[k] != new[k]}
    return {"added": added, "removed": removed, "changed": changed}


def compare(session: Session, older: uuid.UUID, newer: uuid.UUID) -> dict[str, Any]:
    """Nowe, znikające i zmienione hosty, usługi, technologie, nagłówki, tytuły i flagi."""
    runs = {
        r.id: r
        for r in session.scalars(select(DiscoveryRun).where(DiscoveryRun.id.in_((older, newer))))
    }
    if older not in runs or newer not in runs:
        raise LookupError("Nie ma takiego przebiegu")
    a = {o.ip: o for o in session.scalars(select(Observation).where(Observation.run_id == older))}
    b = {o.ip: o for o in session.scalars(select(Observation).where(Observation.run_id == newer))}
    new_hosts = sorted(b.keys() - a.keys(), key=_ip_key)
    gone_hosts = sorted(a.keys() - b.keys(), key=_ip_key)
    changed: list[dict[str, Any]] = []
    for ip in sorted(a.keys() & b.keys(), key=_ip_key):
        old, new = _signature(a[ip]), _signature(b[ip])
        if old == new:
            continue
        entry: dict[str, Any] = {"ip": ip, "hostname": b[ip].hostname or a[ip].hostname}
        for key in ("services", "headers", "titles"):
            diff = _dict_diff(old[key], new[key])
            if any(diff.values()):
                entry[key] = diff
        for key in ("technologies", "flags"):
            plus = sorted(set(new[key]) - set(old[key]))
            minus = sorted(set(old[key]) - set(new[key]))
            if plus or minus:
                entry[key] = {"added": plus, "removed": minus}
        if old["hostname"] != new["hostname"]:
            entry["hostname_change"] = [old["hostname"], new["hostname"]]
        changed.append(entry)

    def brief(o: Observation) -> dict[str, Any]:
        sig = _signature(o)
        return {
            "ip": o.ip,
            "hostname": o.hostname,
            "services": sorted(sig["services"]),
            "technologies": sig["technologies"],
            "flags": sig["flags"],
        }

    return {
        "older": _run_ref(runs[older]),
        "newer": _run_ref(runs[newer]),
        "new_hosts": [brief(b[ip]) for ip in new_hosts],
        "gone_hosts": [brief(a[ip]) for ip in gone_hosts],
        "changed_hosts": changed,
        "counts": {
            "new_hosts": len(new_hosts),
            "gone_hosts": len(gone_hosts),
            "changed_hosts": len(changed),
            "new_services": sum(len(c.get("services", {}).get("added", {})) for c in changed)
            + sum(len(b[ip].services) for ip in new_hosts),
            "gone_services": sum(len(c.get("services", {}).get("removed", {})) for c in changed),
        },
    }


def diff_rows(diff: dict[str, Any]) -> list[dict[str, str]]:
    """Płaska postać różnic do CSV: jeden wiersz na zmianę."""
    rows: list[dict[str, str]] = []
    for host in diff["new_hosts"]:
        rows.append(
            {
                "ip": host["ip"],
                "change": "nowy host",
                "what": ", ".join(host["services"]),
                "before": "",
                "after": "",
            }
        )
    for host in diff["gone_hosts"]:
        rows.append(
            {
                "ip": host["ip"],
                "change": "host zniknął",
                "what": ", ".join(host["services"]),
                "before": "",
                "after": "",
            }
        )
    for host in diff["changed_hosts"]:
        for key, label in (("services", "usługa"), ("headers", "nagłówek"), ("titles", "tytuł")):
            part = host.get(key) or {}
            for name, value in part.get("added", {}).items():
                rows.append(
                    {
                        "ip": host["ip"],
                        "change": f"nowy {label}",
                        "what": name,
                        "before": "",
                        "after": str(value),
                    }
                )
            for name, value in part.get("removed", {}).items():
                rows.append(
                    {
                        "ip": host["ip"],
                        "change": f"zniknął {label}",
                        "what": name,
                        "before": str(value),
                        "after": "",
                    }
                )
            for name, (before, after) in part.get("changed", {}).items():
                rows.append(
                    {
                        "ip": host["ip"],
                        "change": f"zmieniony {label}",
                        "what": name,
                        "before": str(before),
                        "after": str(after),
                    }
                )
        for key, label in (("technologies", "technologia"), ("flags", "flaga")):
            part = host.get(key) or {}
            for name in part.get("added", []):
                rows.append(
                    {
                        "ip": host["ip"],
                        "change": f"nowa {label}",
                        "what": name,
                        "before": "",
                        "after": "",
                    }
                )
            for name in part.get("removed", []):
                rows.append(
                    {
                        "ip": host["ip"],
                        "change": f"zniknęła {label}",
                        "what": name,
                        "before": "",
                        "after": "",
                    }
                )
    return rows


def _run_ref(run: DiscoveryRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "name": run.name,
        "created_at": run.created_at.isoformat(),
        "hosts_up": run.hosts_up,
    }


def _ip_key(ip: str) -> tuple[int, int | str]:
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


@dataclass
class StateCounts:
    active: int = 0
    unstable: int = 0
    unconfirmed: int = 0
    inactive: int = 0
