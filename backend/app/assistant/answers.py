"""Odpowiedzi Sentka. Każdą buduje kod z danych w bazie, bez modelu językowego.

Odpowiedź to kilka krótkich zdań, linki do widoków konsoli i propozycje kolejnych pytań.
Nazwiska tylko dla `personal_data:view` (i bez trybu pseudonimów); w przeciwnym razie
pseudonim „Pracownik #…”. Treści prawnych Sentek nie pisze: terminy to wewnętrzne terminy
naprawy z `rules/reports.yaml`.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assistant.classify import Intent
from app.explainer.service import KIND as EXPLANATION_KIND
from app.iam.redaction import PERSONAL_PERMISSION
from app.iam.tokens import Principal
from app.matching.engine import ACTIVE_STATUSES
from app.models import (
    Asset,
    AssetAssignment,
    AssetSource,
    Finding,
    LLMCache,
    OrgUnit,
    Person,
    Software,
    Vulnerability,
)
from app.org.privacy import pseudonym, record_personal_view
from app.org.shadow import NON_DEVICE_TYPES, SOURCE_LABELS
from app.reports.config import ReportsConfig
from app.reports.current import freshness
from app.reports.facts import Item, deadline, open_items

DISCLAIMER = "Sentek pomaga czytać dane. Nie skanuje sieci i nie zmienia ustawień."
SUGGESTIONS = (
    "Co jest teraz najgroźniejsze?",
    "Ile mamy nieznanych urządzeń?",
    "Do kiedy trzeba naprawić zagrożenia?",
    "Co to jest KEV?",
    "Pokaż samouczek",
)
# Uprawnienie potrzebne do odpowiedzi (poza samym `assistant:use`).
NEEDS: dict[str, str | None] = {
    "top_risks": "findings:read",
    "exposure_check": "findings:read",
    "deadlines": "findings:read",
    "devices": "inventory:read",
    "device_story": "inventory:read",
    "scan_request": "scan:request",
    "explain": None,
    "tour": None,
    "out_of_scope": None,
}
TYPE_LABELS = {
    "host": "host",
    "server": "serwer",
    "workstation": "stacja robocza",
    "laptop": "laptop",
    "network": "urządzenie sieciowe",
    "printer": "drukarka",
    "iot": "urządzenie IoT",
    "cloud": "zasób w chmurze",
    "ai_system": "system AI",
}
LEVEL_ORDER = ("krytyczny", "wysoki", "średni", "niski")


@dataclass
class Answer:
    intent: str
    source: str
    text: list[str]
    links: list[dict[str, str]] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    # Propozycja dla interfejsu: {"kind": "scan_request", ...} albo {"kind": "tour"}.
    # Sentek sam niczego nie uruchamia; akcję potwierdza człowiek przyciskiem.
    action: dict[str, Any] | None = None
    pose: str = "talk"
    freshness: str | None = None
    # Osoby pokazane z nazwiskiem (do audytu `personal_data_viewed`).
    people_shown: list[Person] = field(default_factory=list)


def plural(count: int, one: str, few: str, many: str) -> str:
    if count == 1:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def count(n: int, one: str, few: str, many: str) -> str:
    """„1 urządzenie”, „3 urządzenia”, „5 urządzeń”."""
    return f"{n} {plural(n, one, few, many)}"


ITEMS = ("otwarte zagrożenie", "otwarte zagrożenia", "otwartych zagrożeń")
UNKNOWN = ("nieznane urządzenie", "nieznane urządzenia", "nieznanych urządzeń")


def _suggest(*exclude: str) -> list[str]:
    return [s for s in SUGGESTIONS if s not in exclude][:3]


def _label(item: Item) -> str:
    if item.vuln is not None:
        return item.vuln.cve_id
    if item.finding.type == "exposure":
        return "nieznane urządzenie w sieci"
    return item.finding.type


def _fresh(session: Session, config: ReportsConfig) -> str:
    return freshness(session, config).label()


def no_permission(intent: Intent, permission: str) -> Answer:
    return Answer(
        intent.name,
        intent.source,
        [
            "Twoje konto nie ma dostępu do tych danych, więc nie mogę na to odpowiedzieć.",
            f"Potrzebne uprawnienie: {permission}. O dostęp poproś administratora.",
        ],
        suggestions=_suggest(),
        pose="surprised",
    )


def out_of_scope(intent: Intent) -> Answer:
    if intent.reason == "action":
        text = [
            "Tego nie zrobię: Sentek tylko czyta dane. Nie skanuje sieci i nie zmienia ustawień.",
            "Zmiany wprowadza zespół bezpieczeństwa w konsoli operacyjnej. Mogę pokazać, co "
            "jest najpilniejsze, albo przygotować prośbę o nowe skanowanie do zatwierdzenia.",
        ]
    else:
        text = [
            "Nie umiem jeszcze odpowiedzieć na to pytanie.",
            "Znam się na zagrożeniach, urządzeniach i działach, terminach naprawy, "
            "znaczeniu skrótów i prośbach o nowe skanowanie. Spróbuj na przykład:",
        ]
    return Answer(
        intent.name, intent.source, text, suggestions=list(SUGGESTIONS[:4]), pose="surprised"
    )


def top_risks(session: Session, intent: Intent, config: ReportsConfig, today: date) -> Answer:
    items = open_items(session)
    fresh = _fresh(session, config)
    if not items:
        return Answer(
            intent.name,
            intent.source,
            [
                "Nie ma teraz otwartych zagrożeń. To dobra wiadomość, "
                "ale zależy od świeżości danych."
            ],
            links=[{"label": "Stan bezpieczeństwa", "to": "/"}],
            suggestions=_suggest(),
            pose="thumbs_up",
            freshness=fresh,
        )
    critical = sum(1 for i in items if i.finding.risk_level == "krytyczny")
    kev = sum(1 for i in items if i.vuln is not None and i.vuln.in_kev)
    head = (
        f"Mamy {count(len(items), *ITEMS)}"
        + (
            f", w tym {critical} {plural(critical, 'krytyczne', 'krytyczne', 'krytycznych')}"
            if critical
            else ""
        )
        + "."
    )
    lines = [head]
    if kev:
        lines.append(
            f"{kev} {plural(kev, 'dotyczy', 'dotyczą', 'dotyczy')} podatności "
            "z katalogu KEV, czyli już wykorzystywanych w atakach."
        )
    lines.append("Najpilniejsze:")
    for index, item in enumerate(items[:3], start=1):
        due = deadline(item, config, today)
        lines.append(
            f"{index}. {item.asset.name}: {_label(item)}, ryzyko: {item.finding.risk_level}, "
            f"{item.finding.risk_score:.0f}/100, naprawić do {due.strftime('%d.%m.%Y')}."
        )
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Wszystkie zagrożenia", "to": "/zagrozenia"}],
        suggestions=_suggest("Co jest teraz najgroźniejsze?"),
        pose="point_right",
        freshness=fresh,
    )


def _device_scope(session: Session) -> Any:
    return select(Asset).where(
        Asset.type.not_in(NON_DEVICE_TYPES), Asset.status.in_(("active", "shadow", "missing"))
    )


def devices(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    query = _device_scope(session)
    unit_ids: list[uuid.UUID] = []
    if intent.unit is not None:
        unit_id = uuid.UUID(intent.unit.key)
        children = session.scalars(select(OrgUnit.id).where(OrgUnit.parent_id == unit_id)).all()
        unit_ids = [unit_id, *children]
        query = query.where(Asset.org_unit_id.in_(unit_ids))
    assets = session.scalars(query).all()
    unknown = [a for a in assets if a.status == "shadow"]
    fresh = _fresh(session, config)
    where = f" w dziale {intent.unit.name.removeprefix('Dział ')}" if intent.unit else ""
    if intent.unknown:
        if not unknown:
            text = [
                f"Nie widzę nieznanych urządzeń{where}. "
                "Każde urządzenie z sieci jest w CMDB, AD albo MDM."
            ]
            pose = "thumbs_up"
        else:
            names = ", ".join(a.name for a in unknown[:4])
            text = [
                f"Widzę {count(len(unknown), *UNKNOWN)}{where}: {names}.",
                "Są w sieci, a nie ma ich w CMDB, AD ani MDM. To może być shadow IT albo sprzęt, "
                "którego ktoś nie zgłosił. Zespół IT może je potwierdzić albo wyjaśnić.",
            ]
            pose = "surprised"
        return Answer(
            intent.name,
            intent.source,
            text,
            links=[{"label": "Nieznane urządzenia", "to": "/nieznane"}],
            suggestions=_suggest("Ile mamy nieznanych urządzeń?"),
            pose=pose,
            freshness=fresh,
        )
    by_type: dict[str, int] = defaultdict(int)
    for asset in assets:
        by_type[TYPE_LABELS.get(asset.type, asset.type)] += 1
    kinds = ", ".join(
        f"{label}: {count}" for label, count in sorted(by_type.items(), key=lambda kv: -kv[1])
    )
    text = [
        f"Mamy {len(assets)} {plural(len(assets), 'urządzenie', 'urządzenia', 'urządzeń')}{where}"
        + (f" ({kinds})." if kinds else ".")
    ]
    if unknown:
        text.append(
            f"{len(unknown)} z nich "
            f"{plural(len(unknown), 'jest nieznane', 'są nieznane', 'jest nieznanych')}: "
            "widoczne w sieci, a nie ma ich w CMDB, AD ani MDM."
        )
    if intent.unit is not None:
        link = {
            "label": f"Urządzenia: {intent.unit.name}",
            "to": f"/urzadzenia?dzial={intent.unit.key}",
        }
    else:
        link = {"label": "Wszystkie urządzenia", "to": "/urzadzenia"}
    return Answer(
        intent.name,
        intent.source,
        text,
        links=[link],
        suggestions=_suggest(),
        pose="point_right",
        freshness=fresh,
    )


def _people(session: Session, asset_id: uuid.UUID) -> dict[str, list[Person]]:
    out: dict[str, list[Person]] = defaultdict(list)
    rows = session.execute(
        select(AssetAssignment.role, Person)
        .join(Person, AssetAssignment.person_id == Person.id)
        .where(AssetAssignment.asset_id == asset_id)
        .order_by(Person.pseudonym_no)
    ).all()
    for role, person in rows:
        out[role].append(person)
    return out


def device_story(
    session: Session, intent: Intent, config: ReportsConfig, today: date, *, show_names: bool
) -> Answer:
    if intent.device is None:
        return out_of_scope(intent)
    asset = session.get(Asset, uuid.UUID(intent.device.key))
    if asset is None:
        return out_of_scope(intent)
    unit = session.get(OrgUnit, asset.org_unit_id) if asset.org_unit_id else None
    assigned = _people(session, asset.id)
    shown: list[Person] = []

    def who(people: Sequence[Person]) -> str:
        names = []
        for person in people:
            if show_names:
                shown.append(person)
                names.append(person.full_name)
            else:
                names.append(pseudonym(person))
        return ", ".join(names)

    kind = TYPE_LABELS.get(asset.type, asset.type)
    first = f"{asset.name} to {kind}" + (
        f" w dziale {unit.name.removeprefix('Dział ')}" if unit else ", bez przypisanego działu"
    )
    owner = who(assigned.get("owner", []))
    user = who(assigned.get("user", []))
    if owner:
        first += f". Właściciel: {owner}"
    if user:
        first += f". Używa: {user}"
    text = [first + "."]
    if asset.status == "shadow":
        sources = sorted(
            SOURCE_LABELS.get(s, s)
            for s in session.scalars(
                select(AssetSource.source).where(AssetSource.asset_id == asset.id)
            )
        )
        text.append(
            "To urządzenie nieznane: widać je w sieci (" + ", ".join(sources) + "), "
            "a nie ma go w CMDB, AD ani MDM."
        )
    items = [i for i in open_items(session) if i.asset.id == asset.id]
    if items:
        worst = items[0]
        text.append(
            f"Ma {count(len(items), *ITEMS)}. "
            f"Najpoważniejsze: {_label(worst)}, ryzyko: {worst.finding.risk_level}, "
            f"naprawić do {deadline(worst, config, today).strftime('%d.%m.%Y')}."
        )
        pose = "point_right"
    else:
        text.append("Nie ma otwartych zagrożeń.")
        pose = "thumbs_up"
    return Answer(
        intent.name,
        intent.source,
        text,
        links=[{"label": f"Karta urządzenia {asset.name}", "to": f"/urzadzenia/{asset.id}"}],
        suggestions=[f"Poproś o skanowanie {asset.name}", *_suggest()[:2]],
        pose=pose,
        freshness=_fresh(session, config),
        people_shown=shown,
    )


def _cached_explanation(session: Session, cve_id: str) -> str | None:
    row = session.scalar(
        select(LLMCache)
        .where(
            LLMCache.kind == EXPLANATION_KIND,
            LLMCache.cache_key.like(f"{EXPLANATION_KIND}:{cve_id}:executive:%"),
            LLMCache.validation == "passed",
        )
        .order_by(LLMCache.prompt_version.desc())
        .limit(1)
    )
    return row.content.strip() if row is not None and row.content.strip() else None


def _cve_facts(vuln: Vulnerability) -> list[str]:
    parts = []
    if vuln.cvss_score is not None:
        parts.append(f"ocena powagi CVSS {vuln.cvss_score:.1f} na 10")
    if vuln.in_kev:
        parts.append("jest w katalogu KEV, czyli przestępcy już ją wykorzystują")
    if vuln.epss is not None:
        parts.append(f"szansa wykorzystania w 30 dni według EPSS: {vuln.epss * 100:.0f}%")
    return parts


def explain(
    session: Session, intent: Intent, config: ReportsConfig, principal: Principal
) -> Answer:
    if intent.cve is not None:
        if not principal.can("findings:read"):
            return no_permission(intent, "findings:read")
        vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == intent.cve))
        if vuln is None:
            return Answer(
                intent.name,
                intent.source,
                [
                    f"Nie znam {intent.cve}: nie ma jej w lokalnej bazie podatności "
                    "(NVD, KEV, EPSS).",
                    "Jeśli to nowa podatność, pojawi się po najbliższej synchronizacji feedów.",
                ],
                suggestions=_suggest(),
                pose="surprised",
            )
        text = [f"{vuln.cve_id} to podatność w publicznym rejestrze CVE."]
        facts = _cve_facts(vuln)
        if facts:
            text.append("Najważniejsze fakty: " + "; ".join(facts) + ".")
        cached = _cached_explanation(session, vuln.cve_id)
        if cached:
            text.append(cached)
        return Answer(
            intent.name,
            intent.source,
            text,
            links=[{"label": "Zagrożenia", "to": "/zagrozenia"}],
            suggestions=[f"Czy jesteśmy podatni na {vuln.cve_id}?", *_suggest()[:2]],
        )
    if intent.term is None:
        return out_of_scope(intent)
    term = next((t for t in config.glossary if t.key == intent.term.key), None)
    if term is None:
        return out_of_scope(intent)
    return Answer(
        intent.name,
        intent.source,
        [f"{term.name}: {term.definition}"],
        suggestions=_suggest("Co to jest KEV?"),
    )


def exposure_check(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    fresh = _fresh(session, config)
    caveat = (
        "Sprawdzam inwentarz i wyniki ostatniego skanu, więc odpowiedź jest tak świeża jak te dane."
    )
    if intent.cve is not None:
        vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == intent.cve))
        if vuln is None:
            return Answer(
                intent.name,
                intent.source,
                [
                    f"Nie znam {intent.cve}: nie ma jej w lokalnej bazie podatności.",
                    "Nie potrafię więc powiedzieć, czy nas dotyczy. "
                    "Sprawdzę po synchronizacji feedów.",
                ],
                suggestions=_suggest(),
                pose="surprised",
                freshness=fresh,
            )
        items = open_items(session, cve_ids=[vuln.cve_id])
        if not items:
            return Answer(
                intent.name,
                intent.source,
                [f"Nie widzę {vuln.cve_id} na żadnym naszym urządzeniu.", caveat],
                suggestions=_suggest(),
                pose="thumbs_up",
                freshness=fresh,
            )
        names = ", ".join(sorted({i.asset.name for i in items})[:5])
        hit = len({i.asset.id for i in items})
        return Answer(
            intent.name,
            intent.source,
            [
                f"Tak. {vuln.cve_id} dotyczy "
                f"{count(hit, 'urządzenia', 'urządzeń', 'urządzeń')}: {names}.",
                f"Najwyższe ryzyko: {items[0].finding.risk_level} "
                f"({items[0].finding.risk_score:.0f}/100).",
                caveat,
            ],
            links=[{"label": "Zagrożenia", "to": "/zagrozenia"}],
            suggestions=[f"Co to jest {vuln.cve_id}?", "Do kiedy trzeba naprawić zagrożenia?"],
            pose="surprised",
            freshness=fresh,
        )
    if intent.product is None:
        return out_of_scope(intent)
    product = intent.product.name
    assets = session.scalars(
        select(Asset)
        .join(Software, Software.asset_id == Asset.id)
        .where(Software.product == product)
        .distinct()
    ).all()
    if not assets:
        return Answer(
            intent.name,
            intent.source,
            [f"Nie widzę programu {product} w naszym inwentarzu.", caveat],
            suggestions=_suggest(),
            pose="thumbs_up",
            freshness=fresh,
        )
    ids = [a.id for a in assets]
    open_count = session.scalar(
        select(Finding.id)
        .where(Finding.asset_id.in_(ids), Finding.status.in_(ACTIVE_STATUSES))
        .limit(1)
    )
    names = ", ".join(sorted(a.name for a in assets)[:5])
    text = [
        f"Tak, {product} działa na "
        f"{count(len(assets), 'urządzeniu', 'urządzeniach', 'urządzeniach')}: {names}."
    ]
    text.append(
        "Na tych urządzeniach są otwarte zagrożenia, szczegóły w widoku zagrożeń."
        if open_count
        else "Na tych urządzeniach nie ma otwartych zagrożeń."
    )
    text.append(caveat)
    return Answer(
        intent.name,
        intent.source,
        text,
        links=[{"label": "Urządzenia", "to": "/urzadzenia"}],
        suggestions=_suggest(),
        pose="point_right",
        freshness=fresh,
    )


def deadlines(session: Session, intent: Intent, config: ReportsConfig, today: date) -> Answer:
    items = open_items(session)
    rules = ", ".join(
        f"{level} {count(config.fix_within_days[level], 'dzień', 'dni', 'dni')}"
        for level in LEVEL_ORDER
        if level in config.fix_within_days
    )
    note = (
        f"To wewnętrzne terminy naprawy ({rules}; krócej, gdy CISA wyznaczyła termin w KEV). "
        "Terminów ustawowych tu nie podaję."
    )
    if not items:
        return Answer(
            intent.name,
            intent.source,
            ["Nie ma otwartych zagrożeń, więc nie ma terminów.", note],
            suggestions=_suggest(),
            pose="thumbs_up",
        )
    dated = sorted(((deadline(i, config, today), i) for i in items), key=lambda pair: pair[0])
    lines = ["Najbliższe terminy:"]
    for due, item in dated[:4]:
        lines.append(
            f"{due.strftime('%d.%m.%Y')}: {item.asset.name}, {_label(item)} "
            f"(ryzyko: {item.finding.risk_level})."
        )
    soon = sum(1 for due, _ in dated if (due - today).days <= 7)
    if soon:
        lines.append(
            f"W ciągu tygodnia: {soon} {plural(soon, 'zagrożenie', 'zagrożenia', 'zagrożeń')}."
        )
    lines.append(note)
    return Answer(
        intent.name,
        intent.source,
        lines,
        links=[{"label": "Wszystkie zagrożenia", "to": "/zagrozenia"}],
        suggestions=_suggest("Do kiedy trzeba naprawić zagrożenia?"),
        pose="point_right",
        freshness=_fresh(session, config),
    )


def scan_request(session: Session, intent: Intent, config: ReportsConfig) -> Answer:
    scope: dict[str, str | None]
    if intent.device is not None:
        scope = {
            "scope_kind": "device",
            "scope_ref": intent.device.key,
            "label": f"urządzenie: {intent.device.name}",
        }
    elif intent.unit is not None:
        scope = {
            "scope_kind": "unit",
            "scope_ref": intent.unit.key,
            "label": f"dział: {intent.unit.name}",
        }
    else:
        scope = {"scope_kind": "organization", "scope_ref": None, "label": "cała organizacja"}
    return Answer(
        intent.name,
        intent.source,
        [
            f"Mogę przygotować prośbę o nowe skanowanie ({scope['label']}).",
            "Sam nie skanuję. Prośba trafi do kolejki administratora, a skan ruszy dopiero po jego "
            "zatwierdzeniu. Potwierdź przyciskiem poniżej.",
            _fresh(session, config),
        ],
        action={"kind": "scan_request", **scope},
        suggestions=_suggest(),
        pose="point_left",
    )


def tour(intent: Intent) -> Answer:
    return Answer(
        intent.name,
        intent.source,
        ["Pokażę Ci najważniejsze miejsca w konsoli. Strzałki przechodzą dalej, Esc zamyka samouczek."],
        action={"kind": "tour"},
        suggestions=_suggest("Pokaż samouczek"),
        pose="wave",
    )


def build(
    session: Session,
    intent: Intent,
    config: ReportsConfig,
    principal: Principal,
    today: date,
    *,
    pseudonyms: bool = False,
) -> Answer:
    needed = NEEDS.get(intent.name)
    if needed is not None and not principal.can(needed):
        return no_permission(intent, needed)
    if intent.name == "top_risks":
        return top_risks(session, intent, config, today)
    if intent.name == "devices":
        return devices(session, intent, config)
    if intent.name == "device_story":
        show = principal.can(PERSONAL_PERMISSION) and not pseudonyms
        answer = device_story(session, intent, config, today, show_names=show)
        if answer.people_shown:
            record_personal_view(
                session, actor=principal.actor, people=answer.people_shown, endpoint="assistant"
            )
        return answer
    if intent.name == "explain":
        return explain(session, intent, config, principal)
    if intent.name == "exposure_check":
        return exposure_check(session, intent, config)
    if intent.name == "deadlines":
        return deadlines(session, intent, config, today)
    if intent.name == "scan_request":
        return scan_request(session, intent, config)
    if intent.name == "tour":
        return tour(intent)
    return out_of_scope(intent)
