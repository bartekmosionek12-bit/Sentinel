"""Odpowiedzi Sentka na pytania o bieżące dane: KEV, porty, stan systemu i logowania.

Tak jak reszta odpowiedzi budowane są przez kod z danych w bazie, bez modelu językowego.
Każda kończy się linkiem w Markdownie do widoku konsoli, w którym widać szczegóły.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.matching.engine import ACTIVE_STATUSES
from app.models import (
    Asset,
    AuditLog,
    DiscoveryRun,
    FeedSync,
    Finding,
    Observation,
    ScanRun,
    Software,
    Vulnerability,
)
from app.reports.config import ReportsConfig
from app.reports.freshness import freshness

if TYPE_CHECKING:
    from app.assistant.answers import Answer
    from app.assistant.classify import Intent

FEEDS = ("nvd", "kev", "epss")
LOGIN_ACTIONS = ("console_login", "logout")


def _fmt(moment: object) -> str:
    return moment.strftime("%d.%m.%Y %H:%M") if hasattr(moment, "strftime") else "?"


def kev_list(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    from app.assistant.answers import Answer, count

    rows = session.execute(
        select(Vulnerability.cve_id, Asset.name, Finding.risk_score, Finding.risk_level)
        .join(Finding, Finding.vulnerability_id == Vulnerability.id)
        .join(Asset, Asset.id == Finding.asset_id)
        .where(Vulnerability.in_kev.is_(True), Finding.status.in_(ACTIVE_STATUSES))
        .order_by(Finding.risk_score.desc())
    ).all()
    total_kev = session.scalar(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.in_kev.is_(True))
    )
    fresh = freshness(session, config).label()
    if not rows:
        return Answer(
            intent.name,
            intent.source,
            [
                "Żadna podatność z katalogu CISA KEV nie dotyczy teraz naszych zasobów.",
                f"W lokalnej kopii katalogu jest {total_kev or 0} pozycji. "
                "[Zobacz zagrożenia](/zagrozenia)",
            ],
            pose="thumbs_up",
            freshness=fresh,
        )
    cves = sorted({row.cve_id for row in rows})
    lines = [
        f"Na naszych zasobach jest {count(len(cves), 'podatność', 'podatności', 'podatności')} "
        "z katalogu CISA KEV (aktywnie wykorzystywanych w atakach):"
    ]
    for row in rows[:5]:
        lines.append(
            f"- {row.cve_id} na {row.name}: ryzyko {row.risk_level}, {row.risk_score:.0f}/100"
        )
    if len(rows) > 5:
        lines.append(f"…i {len(rows) - 5} więcej.")
    lines.append("[Szczegóły luk](/zagrozenia)")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Zagrożenia", "to": "/zagrozenia"}],
        suggestions=["Co jest teraz najgroźniejsze?", "Do kiedy trzeba naprawić zagrożenia?"],
        pose="surprised",
        freshness=fresh,
    )


def port_search(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    from app.assistant.answers import Answer, count

    port = intent.port or 0
    hosts: dict[str, str] = {}
    for name, product, version in session.execute(
        select(Asset.name, Software.product, Software.version)
        .join(Software, Software.asset_id == Asset.id)
        .where(Software.port == port, Asset.status.in_(("active", "shadow", "missing")))
    ):
        hosts.setdefault(name, " ".join(p for p in (product, version) if p and p != "unknown"))
    latest = session.scalar(
        select(DiscoveryRun)
        .where(DiscoveryRun.status == "done")
        .order_by(DiscoveryRun.created_at.desc())
        .limit(1)
    )
    if latest is not None:
        for obs in session.scalars(select(Observation).where(Observation.run_id == latest.id)):
            for service in obs.services or []:
                if int(service.get("port") or 0) == port:
                    label = obs.hostname or obs.ip
                    product = " ".join(
                        str(p) for p in (service.get("product"), service.get("version")) if p
                    )
                    hosts.setdefault(label, product or str(service.get("name") or ""))
    fresh = freshness(session, config).label()
    if not hosts:
        return Answer(
            intent.name,
            intent.source,
            [
                f"Nie widzę żadnego hosta z otwartym portem {port} w inwentarzu ani w ostatnim "
                "przebiegu discovery.",
                "[Zobacz w zasobach](/zasoby)",
            ],
            pose="thumbs_up",
            freshness=fresh,
        )
    names = sorted(hosts)
    lines = [f"Port {port} jest otwarty na {count(len(names), 'hoście', 'hostach', 'hostach')}:"]
    for name in names[:8]:
        lines.append(f"- {name}" + (f" ({hosts[name]})" if hosts[name] else ""))
    if len(names) > 8:
        lines.append(f"…i {len(names) - 8} więcej.")
    lines.append("[Zobacz w zasobach](/zasoby) · [Przebiegi discovery](/discovery)")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Zasoby", "to": "/zasoby"}],
        suggestions=["Wskaż hosty Shadow IT", "Co jest teraz najgroźniejsze?"],
        pose="point_right",
        freshness=fresh,
    )


def system_status(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    from app.assistant.answers import Answer

    lines: list[str] = []
    scan = session.scalar(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(1))
    run = session.scalar(select(DiscoveryRun).order_by(DiscoveryRun.created_at.desc()).limit(1))
    if scan is None and run is None:
        lines.append("Nie było jeszcze żadnego skanu.")
    if scan is not None:
        lines.append(f"Ostatni skan: {_fmt(scan.started_at)}, stan: {scan.status}.")
    if run is not None:
        lines.append(
            f"Ostatni przebieg discovery: {_fmt(run.created_at)}, stan: {run.status}, "
            f"aktywne hosty: {run.hosts_up}."
        )
    broken = []
    for feed in FEEDS:
        last = session.scalar(
            select(FeedSync).where(FeedSync.feed == feed).order_by(FeedSync.started_at.desc())
        )
        if last is None:
            broken.append(feed.upper())
            lines.append(f"Feed {feed.upper()}: nie był jeszcze wczytany.")
        else:
            mode = "snapshot offline" if last.mode == "offline" else "online"
            ok = last.status == "ok"
            if not ok:
                broken.append(feed.upper())
            lines.append(
                f"Feed {feed.upper()}: {'działa' if ok else 'błąd'} ({mode}), "
                f"ostatnio {_fmt(last.finished_at or last.started_at)}."
            )
    lines.append(freshness(session, config).label())
    lines.append("[Pulpit ze stanem systemu](/) · [Skany](/skany)")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Pulpit", "to": "/"}],
        suggestions=["Co jest teraz najgroźniejsze?", "Zaproponuj bezpieczny skan L1"],
        pose="surprised" if broken else "thumbs_up",
    )


def audit_logins(session: Session, intent: Intent) -> Answer:
    from app.assistant.answers import Answer

    rows = session.execute(
        select(AuditLog.actor, AuditLog.action, AuditLog.ts)
        .where(AuditLog.action.in_(LOGIN_ACTIONS))
        .order_by(AuditLog.ts.desc())
        .limit(20)
    ).all()
    if not rows:
        return Answer(
            intent.name,
            intent.source,
            [
                "Dziennik audytu nie ma jeszcze wpisów o wejściach do konsoli.",
                "[Dziennik audytu](/audyt)",
            ],
            pose="surprised",
        )
    seen: dict[str, tuple[str, object]] = {}
    for actor, action, created in rows:
        seen.setdefault(actor, (action, created))
    lines = ["Ostatnie wejścia do konsoli według dziennika audytu:"]
    for actor, (action, when) in list(seen.items())[:5]:
        what = "wejście do konsoli" if action == "console_login" else "wylogowanie"
        lines.append(f"- {actor.removeprefix('user:')}: {what}, {_fmt(when)}")
    lines.append("[Dziennik audytu](/audyt)")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Dziennik audytu", "to": "/audyt"}],
        suggestions=["Sprawdź stan feedów i systemu"],
        pose="point_right",
    )
