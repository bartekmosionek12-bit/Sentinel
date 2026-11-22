"""Odpowiedzi Sentka o wynikach discovery: zmiany, hosty niestabilne, panele i staging,
certyfikaty TLS, technologie, eksport do DefectDojo i uprawnienia pytającego.

Tak jak reszta odpowiedzi budowane są przez kod z danych w bazie, bez modelu językowego
i bez ruchu sieciowego. Każda kończy się linkiem w Markdownie do widoku konsoli.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.discovery.analysis import compare, host_states
from app.models import DefectDojoExport, DiscoveryRun, Observation

if TYPE_CHECKING:
    from app.assistant.answers import Answer
    from app.assistant.classify import Intent
    from app.iam.tokens import Principal

DONE = ("done", "stopped")
FLAG_LABELS = {
    "panel": "panele administracyjne lub logowania",
    "staging": "środowiska testowe / staging",
    "security_headers": "braki nagłówków bezpieczeństwa",
    "cookie": "ciekawe ciasteczka",
}
CERT_WARN_DAYS = 30
ROLE_LABELS = {
    "administrator": "administrator",
    "editor": "editor",
    "modifier": "modifier",
    "viewer": "viewer",
}
# Co dana grupa uprawnień pozwala zrobić w konsoli (po ludzku, bez nazw technicznych).
CAPABILITIES = (
    ("scan:read", "przeglądać przebiegi discovery i skany"),
    ("scan:run", "uruchamiać skany i edytować sygnatury"),
    ("findings:update", "edytować wyniki (nazwa, krytyczność, status, notatka)"),
    ("inventory:write", "importować wyniki i cele"),
    ("reports:export", "eksportować wyniki"),
    ("defectdojo:export", "wysyłać wyniki do DefectDojo"),
    ("audit:read", "czytać dziennik audytu"),
    ("agent:task", "zlecać zadania agentowi"),
)


def _latest_runs(session: Session, limit: int) -> list[DiscoveryRun]:
    return list(
        session.scalars(
            select(DiscoveryRun)
            .where(DiscoveryRun.status.in_(DONE))
            .order_by(DiscoveryRun.created_at.desc())
            .limit(limit)
        )
    )


def _no_runs(intent: Intent) -> Answer:
    from app.assistant.answers import Answer

    return Answer(
        intent.name,
        intent.source,
        [
            "Nie ma jeszcze zakończonego przebiegu discovery, więc nie mam z czego odpowiedzieć.",
            "[Przebiegi discovery](/discovery)",
        ],
        suggestions=["Zaproponuj bezpieczny skan L1", "Kiedy był ostatni skan?"],
        pose="surprised",
    )


def _host(obs: Observation) -> str:
    return f"{obs.hostname} ({obs.ip})" if obs.hostname else obs.ip


def _brief(host: dict[str, Any]) -> str:
    name = f"{host['hostname']} ({host['ip']})" if host.get("hostname") else host["ip"]
    services = ", ".join(host.get("services") or [])
    return name + (f": {services}" if services else "")


def discovery_changes(session: Session, intent: Intent) -> Answer:
    from app.assistant.answers import Answer, count

    runs = _latest_runs(session, 2)
    if not runs:
        return _no_runs(intent)
    if len(runs) < 2:
        return Answer(
            intent.name,
            intent.source,
            [
                "Jest dopiero jeden zakończony przebieg discovery, więc nie ma z czym porównać.",
                "Po kolejnym skanie pokażę nowe, znikające i zmienione hosty oraz usługi.",
                "[Przebiegi discovery](/discovery)",
            ],
            suggestions=["Zaproponuj bezpieczny skan L1"],
            pose="thumbs_up",
        )
    newer, older = runs
    diff = compare(session, older.id, newer.id)
    counts = diff["counts"]
    to = f"/discovery/porownanie?older={older.id}&newer={newer.id}"
    if not any(counts.values()):
        return Answer(
            intent.name,
            intent.source,
            [
                f"Między przebiegami z {_fmt(older.created_at)} i {_fmt(newer.created_at)} "
                "nic się nie zmieniło: te same hosty, usługi, technologie i flagi.",
                f"[Porównanie przebiegów]({to})",
            ],
            links=[{"label": "Porównanie", "to": to}],
            pose="thumbs_up",
        )
    new = count(counts["new_hosts"], "nowy host", "nowe hosty", "nowych hostów")
    gone = count(counts["gone_hosts"], "znikający host", "znikające hosty", "znikających hostów")
    changed = count(
        counts["changed_hosts"], "zmieniony host", "zmienione hosty", "zmienionych hostów"
    )
    lines = [
        f"Zmiany między przebiegami z {_fmt(older.created_at)} i {_fmt(newer.created_at)}: "
        f"{new}, {gone}, {changed}."
    ]
    for host in diff["new_hosts"][:3]:
        lines.append(f"- nowy: {_brief(host)}")
    for host in diff["gone_hosts"][:3]:
        lines.append(f"- zniknął: {_brief(host)}")
    for entry in diff["changed_hosts"][:4]:
        services = entry.get("services", {})
        parts = [f"+{port}" for port in sorted(services.get("added", {}))]
        parts += [f"−{port}" for port in sorted(services.get("removed", {}))]
        parts += [f"zmiana {port}" for port in sorted(services.get("changed", {}))]
        tech = entry.get("technologies", {})
        parts += [f"+{t}" for t in tech.get("added", [])]
        parts += [f"−{t}" for t in tech.get("removed", [])]
        name = f"{entry['hostname']} ({entry['ip']})" if entry.get("hostname") else entry["ip"]
        lines.append(f"- zmieniony: {name}" + (f": {', '.join(parts)}" if parts else ""))
    lines.append(f"[Porównanie przebiegów]({to})")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Porównanie", "to": to}],
        suggestions=["Które hosty są niestabilne?", "Gdzie są panele administracyjne?"],
        pose="surprised",
    )


def unstable_hosts(session: Session, intent: Intent) -> Answer:
    from app.assistant.answers import Answer, count

    states = host_states(session)
    if not states:
        return _no_runs(intent)
    names: dict[str, str] = {}
    for ip, hostname in session.execute(
        select(Observation.ip, Observation.hostname).where(Observation.hostname.is_not(None))
    ):
        if hostname:
            names.setdefault(ip, hostname)
    groups: dict[str, list[str]] = {"unstable": [], "unconfirmed": [], "inactive": []}
    for ip, state in sorted(states.items()):
        if state["state"] in groups:
            history = "".join("✓" if seen else "✗" for seen in reversed(state["history"]))
            label = f"{names[ip]} ({ip})" if ip in names else ip
            groups[state["state"]].append(f"{label}, historia {history}")
    active = sum(1 for s in states.values() if s["state"] == "active")
    if not any(groups.values()):
        return Answer(
            intent.name,
            intent.source,
            [
                f"Wszystkie znane hosty ({active}) odpowiadają stabilnie w ostatnich przebiegach.",
                "[Stany hostów](/discovery/porownanie)",
            ],
            pose="thumbs_up",
        )
    lines = [
        f"Stany hostów: {active} aktywnych, {len(groups['unstable'])} niestabilnych, "
        f"{len(groups['unconfirmed'])} niepotwierdzonych, {len(groups['inactive'])} nieaktywnych."
    ]
    for key, title in (
        ("unstable", "niestabilny"),
        ("unconfirmed", "niepotwierdzony"),
        ("inactive", "nieaktywny"),
    ):
        for row in groups[key][:4]:
            lines.append(f"- {title}: {row}")
    rest = sum(len(v) for v in groups.values()) - sum(min(len(v), 4) for v in groups.values())
    if rest > 0:
        lines.append(f"…i {count(rest, 'kolejny', 'kolejne', 'kolejnych')}.")
    lines.append("Historia od najstarszego przebiegu: ✓ odpowiedział, ✗ brak odpowiedzi.")
    lines.append("[Stany hostów](/discovery/porownanie)")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Porównanie i stany", "to": "/discovery/porownanie"}],
        suggestions=["Co się zmieniło od ostatniego skanu?"],
        pose="point_right",
    )


def _latest_observations(session: Session) -> tuple[DiscoveryRun | None, list[Observation]]:
    runs = _latest_runs(session, 1)
    if not runs:
        return None, []
    run = runs[0]
    return run, list(session.scalars(select(Observation).where(Observation.run_id == run.id)))


def web_flags(session: Session, intent: Intent) -> Answer:
    from app.assistant.answers import Answer, count

    run, observations = _latest_observations(session)
    if run is None:
        return _no_runs(intent)
    kinds = (intent.flag_kind,) if intent.flag_kind else ("panel", "staging")
    found: list[str] = []
    for obs in observations:
        for flag in obs.flags or []:
            if flag.get("kind") in kinds:
                evidence = "; ".join(str(e) for e in (flag.get("evidence") or [])[:2])
                found.append(
                    f"{_host(obs)}: {flag.get('label') or flag.get('kind')}"
                    + (f" ({evidence})" if evidence else "")
                )
    what = " i ".join(FLAG_LABELS.get(k, k) for k in kinds)
    to = f"/discovery/{run.id}"
    if not found:
        return Answer(
            intent.name,
            intent.source,
            [
                f"W ostatnim przebiegu discovery ({_fmt(run.created_at)}) nie ma flag: {what}.",
                f"[Przebieg discovery]({to})",
            ],
            pose="thumbs_up",
        )
    hits = count(len(found), "znalezisko", "znaleziska", "znalezisk")
    lines = [f"W ostatnim przebiegu ({_fmt(run.created_at)}) {what}: {hits}."]
    lines += [f"- {row}" for row in found[:6]]
    if len(found) > 6:
        lines.append(f"…i {len(found) - 6} więcej.")
    lines.append(f"[Przebieg discovery z dowodami]({to})")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Przebieg discovery", "to": to}],
        suggestions=["Jakie technologie wykryto?", "Czy jakieś certyfikaty wygasają?"],
        pose="point_right",
    )


def _parse(moment: object) -> datetime | None:
    if not isinstance(moment, str):
        return None
    try:
        parsed = datetime.fromisoformat(moment)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def tls_certs(session: Session, intent: Intent, now: datetime | None = None) -> Answer:
    from app.assistant.answers import Answer

    run, observations = _latest_observations(session)
    if run is None:
        return _no_runs(intent)
    now = now or datetime.now(UTC)
    expired: list[str] = []
    soon: list[str] = []
    self_signed: list[str] = []
    total = 0
    for obs in observations:
        for item in obs.http or []:
            tls = item.get("tls") or {}
            if not tls:
                continue
            total += 1
            where = f"{_host(obs)}:{item.get('port')}"
            end = _parse(tls.get("not_after"))
            if end is not None and end < now:
                expired.append(f"{where}, wygasł {end:%d.%m.%Y}")
            elif end is not None and end < now + timedelta(days=CERT_WARN_DAYS):
                soon.append(f"{where}, wygasa {end:%d.%m.%Y}")
            if tls.get("self_signed"):
                self_signed.append(where)
    to = f"/discovery/{run.id}"
    if total == 0:
        return Answer(
            intent.name,
            intent.source,
            [
                f"W ostatnim przebiegu ({_fmt(run.created_at)}) żadna usługa nie podała "
                "certyfikatu TLS.",
                f"[Przebieg discovery]({to})",
            ],
            pose="thumbs_up",
        )
    lines = [
        f"Certyfikaty TLS w ostatnim przebiegu: {total}, wygasłe: {len(expired)}, "
        f"wygasające w {CERT_WARN_DAYS} dni: {len(soon)}, samopodpisane: {len(self_signed)}."
    ]
    lines += [f"- wygasły: {row}" for row in expired[:4]]
    lines += [f"- wygasa: {row}" for row in soon[:4]]
    lines += [f"- samopodpisany: {row}" for row in self_signed[:4]]
    lines.append(f"[Przebieg discovery]({to})")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Przebieg discovery", "to": to}],
        suggestions=["Gdzie są panele administracyjne?"],
        pose="surprised" if expired or soon else "thumbs_up",
    )


def technologies(session: Session, intent: Intent) -> Answer:
    from app.assistant.answers import Answer, count

    run, observations = _latest_observations(session)
    if run is None:
        return _no_runs(intent)
    hosts: dict[str, set[str]] = {}
    for obs in observations:
        for item in obs.http or []:
            for tech in item.get("technologies") or []:
                hosts.setdefault(str(tech), set()).add(_host(obs))
    products: Counter[str] = Counter()
    for obs in observations:
        for service in obs.services or []:
            product = service.get("product")
            if product:
                products[str(product)] += 1
    to = f"/discovery/{run.id}"
    if not hosts and not products:
        return Answer(
            intent.name,
            intent.source,
            [
                f"W ostatnim przebiegu ({_fmt(run.created_at)}) nie rozpoznano technologii.",
                "Własne reguły rozpoznawania dodasz w sygnaturach detekcyjnych.",
                "[Sygnatury detekcyjne](/discovery/sygnatury)",
            ],
            pose="surprised",
        )
    lines = [f"Technologie z ostatniego przebiegu ({_fmt(run.created_at)}):"]
    for tech, where in sorted(hosts.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:6]:
        sample = ", ".join(sorted(where)[:2])
        lines.append(f"- {tech}: {count(len(where), 'host', 'hosty', 'hostów')} ({sample})")
    if products:
        top = ", ".join(f"{name} ×{n}" for name, n in products.most_common(5))
        lines.append(f"Oprogramowanie usług według nmapa: {top}.")
    lines.append(f"[Przebieg discovery]({to}) · [Sygnatury detekcyjne](/discovery/sygnatury)")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Przebieg discovery", "to": to}],
        suggestions=["Gdzie są panele administracyjne?", "Co się zmieniło od ostatniego skanu?"],
        pose="point_right",
    )


def defectdojo_status(session: Session, intent: Intent) -> Answer:
    from app.assistant.answers import Answer, count

    exported = session.scalar(select(func.count()).select_from(DefectDojoExport)) or 0
    last = session.scalar(select(func.max(DefectDojoExport.exported_at)))
    if not exported:
        lines = [
            "Do DefectDojo nie wysłano jeszcze żadnej obserwacji.",
            "Wysyłka: przebieg discovery → zaznacz hosty → „Wyślij do DefectDojo”. "
            "Każda obserwacja trafia raz, jako finding Info.",
        ]
    else:
        lines = [
            f"Do DefectDojo wysłano {count(exported, 'obserwację', 'obserwacje', 'obserwacji')}, "
            f"ostatnio {_fmt(last)}.",
            "Powtórna wysyłka tych samych obserwacji nie tworzy duplikatów.",
        ]
    lines.append("Stan połączenia z lokalnym DefectDojo widać na pulpicie. [Pulpit](/)")
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Przebiegi discovery", "to": "/discovery"}],
        suggestions=["Co się zmieniło od ostatniego skanu?"],
        pose="point_right",
    )


def my_access(intent: Intent, principal: Principal) -> Answer:
    from app.assistant.answers import Answer

    roles = ", ".join(ROLE_LABELS.get(r, r) for r in sorted(principal.roles)) or "brak roli"
    can = [label for perm, label in CAPABILITIES if principal.can(perm)]
    cannot = [label for perm, label in CAPABILITIES if not principal.can(perm)]
    lines = [f"Jesteś zalogowany jako {principal.username}, rola: {roles}."]
    if can:
        lines.append("Możesz: " + "; ".join(can) + ".")
    if cannot:
        lines.append("Nie możesz: " + "; ".join(cannot) + ".")
    lines.append(
        "Uprawnienia sprawdza backend przy każdym żądaniu; odmowa trafia do dziennika audytu."
    )
    return Answer(
        intent.name,
        intent.source,
        lines,
        suggestions=["Jak działa ta konsola?"],
        pose="talk",
    )


def _fmt(moment: object) -> str:
    return moment.strftime("%d.%m.%Y %H:%M") if hasattr(moment, "strftime") else "?"
