"""Raport z przebiegu discovery (brief: „dashboard lub raport pokazujący najważniejsze zmiany”,
„eksport wyników do JSON lub CSV”, kryterium 10 „czytelność raportu”).

Jeden zestaw danych, trzy formaty:

- JSON: cały raport, do dalszej automatyzacji,
- CSV: jeden wiersz na pozycję raportu (sekcja, host, port, opis), do arkusza,
- HTML: samodzielna strona do czytania i druku (w przeglądarce „Drukuj → PDF”).

Raport liczymy z tych samych danych co konsola (`present`, `compare`, stany hostów), więc
uwzględnia ręczne poprawki: nazwę hosta, tagi, krytyczność i ukryte flagi.
"""

from __future__ import annotations

import csv
import html
import io
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.discovery.analysis import compare
from app.models import DiscoveryRun
from app.models.base import utcnow

# Ocena „ciekawości” hosta dla analityka (brief: mile widziane). Wagi są jawne w raporcie.
WEIGHTS: dict[str, int] = {
    "panel": 3,
    "staging": 3,
    "tls": 2,
    "header": 1,
    "cookie": 1,
    "security_headers": 1,
}
STATE_WEIGHT = {"unstable": 1, "unconfirmed": 1}
CRITICALITY_WEIGHT = {"wysoka": 2, "krytyczna": 3}
NEW_HOST_WEIGHT = 2
CSV_COLUMNS = ("section", "ip", "hostname", "port", "item", "detail")


def previous_run(session: Session, run: DiscoveryRun) -> DiscoveryRun | None:
    """Ostatni wcześniejszy przebieg ze skanu, który doszedł do końca albo do końca okna."""
    return session.scalar(
        select(DiscoveryRun)
        .where(
            DiscoveryRun.created_at < run.created_at,
            DiscoveryRun.status.in_(("done", "stopped", "paused")),
            DiscoveryRun.id != run.id,
        )
        .order_by(DiscoveryRun.created_at.desc())
        .limit(1)
    )


def _score(host: dict[str, Any], new: bool) -> tuple[int, list[str]]:
    points, why = 0, []
    for flag in host.get("flags") or []:
        weight = WEIGHTS.get(flag.get("kind", ""), 0)
        if weight:
            points += weight
            why.append(f"{flag.get('label') or flag['kind']} (+{weight})")
    state = (host.get("state") or {}).get("state")
    if state in STATE_WEIGHT:
        points += STATE_WEIGHT[state]
        why.append(f"stan: {(host.get('state') or {}).get('label', state)} (+1)")
    weight = CRITICALITY_WEIGHT.get(str(host.get("criticality") or ""), 0)
    if weight:
        points += weight
        why.append(f"krytyczność {host['criticality']} (+{weight})")
    if new:
        points += NEW_HOST_WEIGHT
        why.append(f"nowy host (+{NEW_HOST_WEIGHT})")
    return points, why


def _service_label(service: dict[str, Any]) -> str:
    product = " ".join(p for p in (service.get("product"), service.get("version")) if p)
    name = service.get("name") or "?"
    return f"{service['port']}/{service.get('protocol', 'tcp')} {name}" + (
        f" · {product}" if product else ""
    )


def _tls_items(host: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    items = []
    for item in host.get("http") or []:
        tls = item.get("tls") or {}
        if not tls:
            continue
        problems = []
        not_after = tls.get("not_after")
        if not_after:
            try:
                expires = datetime.fromisoformat(str(not_after))
            except ValueError:
                expires = None
            if expires is not None:
                days = (expires - now).days
                if days < 0:
                    problems.append(f"wygasł {-days} dni temu")
                elif days <= 30:
                    problems.append(f"wygasa za {days} dni")
        if tls.get("self_signed"):
            problems.append("samopodpisany")
        if problems:
            items.append({"port": item.get("port"), "detail": ", ".join(problems)})
    return items


def build_report(
    session: Session, run: DiscoveryRun, hosts: list[dict[str, Any]], run_out: dict[str, Any]
) -> dict[str, Any]:
    now = utcnow()
    before = previous_run(session, run)
    changes = compare(session, before.id, run.id) if before is not None else None
    new_ips = {h["ip"] for h in (changes or {}).get("new_hosts", [])}

    services = [s for h in hosts for s in h.get("services") or []]
    flags = Counter(f.get("kind", "") for h in hosts for f in h.get("flags") or [])
    states = Counter((h.get("state") or {}).get("state", "brak") for h in hosts)
    technologies = Counter(t for h in hosts for t in h.get("technologies") or [])
    groups: dict[str, list[str]] = defaultdict(list)
    for host in hosts:
        for service in host.get("services") or []:
            groups[_service_label(service)].append(host["ip"])

    priority = []
    for host in hosts:
        points, why = _score(host, host["ip"] in new_ips)
        if points:
            priority.append(
                {
                    "ip": host["ip"],
                    "hostname": host.get("hostname"),
                    "score": points,
                    "reasons": why,
                    "tags": host.get("tags") or [],
                }
            )
    priority.sort(key=lambda p: (-p["score"], p["ip"]))

    findings = [
        {
            "ip": host["ip"],
            "hostname": host.get("hostname"),
            "kind": flag.get("kind"),
            "label": flag.get("label"),
            "evidence": flag.get("evidence") or [],
            "confidence": flag.get("confidence"),
        }
        for host in hosts
        for flag in host.get("flags") or []
    ]
    tls = [
        {"ip": host["ip"], "hostname": host.get("hostname"), **item}
        for host in hosts
        for item in _tls_items(host, now)
    ]
    unstable = [
        {
            "ip": host["ip"],
            "hostname": host.get("hostname"),
            "state": (host.get("state") or {}).get("label"),
            "history": (host.get("state") or {}).get("history") or [],
            "time_profile": ((host.get("state") or {}).get("time_profile") or {}).get("label"),
        }
        for host in hosts
        if (host.get("state") or {}).get("state") in ("unstable", "unconfirmed", "inactive")
    ]
    return {
        "generated_at": now.isoformat(),
        "run": run_out,
        "summary": {
            "hosts": len(hosts),
            "services": len(services),
            "web_services": sum(len(h.get("http") or []) for h in hosts),
            "technologies": len(technologies),
            "flags": dict(sorted(flags.items())),
            "states": dict(sorted(states.items())),
            "edited_hosts": sum(1 for h in hosts if h.get("edited")),
        },
        "changes": None
        if changes is None
        else {
            "compared_with": changes["older"],
            "counts": changes["counts"],
            "new_hosts": changes["new_hosts"],
            "gone_hosts": changes["gone_hosts"],
            "changed_hosts": changes["changed_hosts"],
        },
        "priority": {"weights": {**WEIGHTS, "nowy host": NEW_HOST_WEIGHT}, "hosts": priority},
        "findings": findings,
        "tls": tls,
        "unstable_hosts": unstable,
        "service_groups": [
            {"service": label, "count": len(ips), "hosts": sorted(ips)}
            for label, ips in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        ],
        "technologies": [
            {"name": name, "hosts": count} for name, count in technologies.most_common()
        ],
    }


def report_rows(report: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def add(
        section: str,
        ip: str = "",
        hostname: Any = "",
        port: Any = "",
        item: Any = "",
        detail: Any = "",
    ) -> None:
        rows.append(
            {
                "section": section,
                "ip": ip,
                "hostname": str(hostname or ""),
                "port": "" if port is None else str(port),
                "item": str(item),
                "detail": str(detail),
            }
        )

    summary = report["summary"]
    for key in ("hosts", "services", "web_services", "technologies", "edited_hosts"):
        add("podsumowanie", item=key, detail=summary[key])
    for state, n in summary["states"].items():
        add("podsumowanie", item=f"stan:{state}", detail=n)
    changes = report["changes"]
    if changes:
        for host in changes["new_hosts"]:
            add(
                "zmiany",
                host["ip"],
                host.get("hostname"),
                item="nowy host",
                detail="; ".join(host["services"]),
            )
        for host in changes["gone_hosts"]:
            add(
                "zmiany",
                host["ip"],
                host.get("hostname"),
                item="zniknął",
                detail="; ".join(host["services"]),
            )
        for host in changes["changed_hosts"]:
            services = host.get("services") or {}
            for port, label in (services.get("added") or {}).items():
                add("zmiany", host["ip"], host.get("hostname"), port, "nowa usługa", label)
            for port, label in (services.get("removed") or {}).items():
                add("zmiany", host["ip"], host.get("hostname"), port, "usługa zniknęła", label)
            for port, (old, new) in (services.get("changed") or {}).items():
                add(
                    "zmiany",
                    host["ip"],
                    host.get("hostname"),
                    port,
                    "zmiana usługi",
                    f"{old} → {new}",
                )
    for host in report["priority"]["hosts"]:
        add(
            "priorytet",
            host["ip"],
            host.get("hostname"),
            item=host["score"],
            detail="; ".join(host["reasons"]),
        )
    for f in report["findings"]:
        add(
            "flagi",
            f["ip"],
            f.get("hostname"),
            item=f.get("label") or f.get("kind"),
            detail="; ".join(f["evidence"]),
        )
    for t in report["tls"]:
        add("tls", t["ip"], t.get("hostname"), t.get("port"), "certyfikat", t["detail"])
    for u in report["unstable_hosts"]:
        add(
            "stany",
            u["ip"],
            u.get("hostname"),
            item=u.get("state"),
            detail="".join("✓" if x else "✗" for x in u["history"]),
        )
    for g in report["service_groups"]:
        add("usługi", item=g["service"], detail=f"{g['count']}: {', '.join(g['hosts'][:50])}")
    for t in report["technologies"]:
        add("technologie", item=t["name"], detail=t["hosts"])
    return rows


def report_csv(report: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in report_rows(report):
        # Komórka zaczynająca się od =, +, - albo @ to w arkuszu formuła: neutralizujemy.
        writer.writerow(
            {k: ("'" + v if v[:1] in ("=", "+", "-", "@") else v) for k, v in row.items()}
        )
    return out.getvalue()


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "<p class='muted'>Brak pozycji.</p>"
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>" for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def report_html(report: dict[str, Any]) -> str:
    run, summary, changes = report["run"], report["summary"], report["changes"]
    e = html.escape
    tiles = [
        ("Aktywne hosty", summary["hosts"]),
        ("Usługi", summary["services"]),
        ("Usługi WWW", summary["web_services"]),
        ("Technologie", summary["technologies"]),
        ("Flagi", sum(summary["flags"].values())),
    ]
    parts = [
        "<!doctype html><html lang='pl'><head><meta charset='utf-8'>",
        f"<title>Raport discovery: {e(run.get('name') or '')}</title>",
        "<style>body{font:14px/1.45 system-ui,sans-serif;margin:24px;color:#111}"
        "h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:24px 0 8px;"
        "border-bottom:1px solid #ccc;padding-bottom:4px}.muted{color:#666}"
        ".tiles{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.tile{border:1px solid #ccc;"
        "padding:8px 12px;min-width:110px}.tile b{display:block;font-size:22px}"
        "table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #ddd;"
        "padding:4px 6px;text-align:left;vertical-align:top}th{background:#f3f3f3}"
        "@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}</style>",
        "</head><body>",
        f"<h1>Raport discovery: {e(run.get('name') or str(run.get('id')))}</h1>",
        f"<p class='muted'>Przebieg {e(str(run.get('id')))} · status {e(str(run.get('status')))}"
        f" · start {e(str(run.get('created_at')))} · adresów {run.get('addresses_total')}"
        f" · czas {run.get('duration_seconds') or '–'} s · wygenerowano "
        f"{e(report['generated_at'])}</p>",
        "<div class='tiles'>"
        + "".join(f"<div class='tile'><b>{v}</b>{e(k)}</div>" for k, v in tiles)
        + "</div>",
        "<h2>Najważniejsze zmiany</h2>",
    ]
    if changes is None:
        parts.append("<p class='muted'>To pierwszy przebieg: nie ma z czym porównać.</p>")
    else:
        c = changes["counts"]
        older = changes["compared_with"]
        parts.append(
            f"<p>Porównanie z przebiegiem „{e(str(older.get('name')))}” "
            f"({e(str(older.get('created_at')))}): nowe hosty {c['new_hosts']}, zniknęło "
            f"{c['gone_hosts']}, zmienione {c['changed_hosts']}, nowe usługi "
            f"{c['new_services']}, zniknęło usług {c['gone_services']}.</p>"
        )
        rows = [
            ["nowy host", h["ip"], h.get("hostname") or "", ", ".join(h["services"])]
            for h in changes["new_hosts"]
        ]
        rows += [
            ["zniknął", h["ip"], h.get("hostname") or "", ", ".join(h["services"])]
            for h in changes["gone_hosts"]
        ]
        for h in changes["changed_hosts"]:
            services = h.get("services") or {}
            detail = [f"+{k} {v}" for k, v in (services.get("added") or {}).items()]
            detail += [f"−{k} {v}" for k, v in (services.get("removed") or {}).items()]
            detail += [f"{k}: {a} → {b}" for k, (a, b) in (services.get("changed") or {}).items()]
            for key in ("technologies", "flags"):
                if key in h:
                    detail += [f"+{x}" for x in h[key]["added"]] + [
                        f"−{x}" for x in h[key]["removed"]
                    ]
            rows.append(["zmieniony", h["ip"], h.get("hostname") or "", "; ".join(detail)])
        parts.append(_table(["Zmiana", "Adres", "Nazwa", "Szczegóły"], rows))
    weights = ", ".join(f"{k} {v}" for k, v in report["priority"]["weights"].items())
    parts += [
        "<h2>Priorytet analityczny</h2>",
        f"<p class='muted'>Punkty za: {e(weights)}; stan niestabilny lub niepotwierdzony 1; "
        "krytyczność wysoka 2, krytyczna 3.</p>",
        _table(
            ["Punkty", "Adres", "Nazwa", "Dlaczego"],
            [
                [p["score"], p["ip"], p.get("hostname") or "", "; ".join(p["reasons"])]
                for p in report["priority"]["hosts"][:50]
            ],
        ),
        "<h2>Flagi z fingerprintu</h2>",
        _table(
            ["Adres", "Nazwa", "Flaga", "Dowód", "Pewność"],
            [
                [
                    f["ip"],
                    f.get("hostname") or "",
                    f.get("label") or f.get("kind"),
                    "; ".join(f["evidence"]),
                    f.get("confidence") or "",
                ]
                for f in report["findings"]
            ],
        ),
        "<h2>Certyfikaty TLS</h2>",
        _table(
            ["Adres", "Port", "Problem"],
            [[t["ip"], t.get("port"), t["detail"]] for t in report["tls"]],
        ),
        "<h2>Hosty niestabilne, niepotwierdzone i nieaktywne</h2>",
        _table(
            ["Adres", "Nazwa", "Stan", "Historia", "Pora dnia"],
            [
                [
                    u["ip"],
                    u.get("hostname") or "",
                    u.get("state") or "",
                    "".join("✓" if x else "✗" for x in u["history"]),
                    u.get("time_profile") or "",
                ]
                for u in report["unstable_hosts"]
            ],
        ),
        "<h2>Usługi (grupy)</h2>",
        _table(
            ["Usługa", "Hostów", "Adresy"],
            [
                [g["service"], g["count"], ", ".join(g["hosts"][:30])]
                for g in report["service_groups"]
            ],
        ),
        "<h2>Technologie</h2>",
        _table(
            ["Technologia", "Hostów"], [[t["name"], t["hosts"]] for t in report["technologies"]]
        ),
        "<p class='muted'>Sentinel ASI. Raport z danych przebiegu i ręcznych poprawek. "
        "Zawiera dane o infrastrukturze: przechowuj i przekazuj zgodnie z polityką "
        "organizacji.</p></body></html>",
    ]
    return "".join(parts)
