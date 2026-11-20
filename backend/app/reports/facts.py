"""Fakty raportu: wybiera i liczy je kod, nie model.

Zasoby i osoby występują w faktach jako tokeny `asset_<n>` i `person_<n>`; model nigdy nie
widzi nazw hostów, adresów ani nazwisk (docs/ARCHITECTURE.md, sekcja 12.2). Znaczenie tokenów
trzyma `entities`, a nazwy podstawia dopiero API.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.explainer.context import severity_label
from app.matching.engine import ACTIVE_STATUSES
from app.models import Asset, Finding, Vulnerability
from app.reports.config import QUESTION_KEYS, LightRule, ReportsConfig
from app.scoring.engine import LEVEL_ORDER

EXPOSURE = {"internet": "dostępny z internetu", "internal": "tylko w sieci wewnętrznej"}
DESCRIPTION_MAX_CHARS = 300


@dataclass(frozen=True)
class Item:
    """Otwarte zagrożenie w zakresie raportu (wiersz warstwy technicznej)."""

    finding: Finding
    asset: Asset
    vuln: Vulnerability | None


@dataclass
class ReportData:
    title: str
    light: str
    light_reason: str
    facts: dict[str, list[str]]
    entities: dict[str, dict[str, Any]]
    technical: dict[str, Any]
    # Odpowiedzi z szablonu: zawsze dostępne, także bez modelu; model może je zastąpić.
    template: dict[str, str] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)

    @property
    def products(self) -> list[str]:
        return [str(row["product"]) for row in self.technical.get("rows", []) if row.get("product")]


class Tokens:
    """Nadaje tokeny w kolejności pojawienia się: asset_1, asset_2, person_1…"""

    def __init__(self) -> None:
        self.entities: dict[str, dict[str, Any]] = {}
        self._by_key: dict[tuple[str, str], str] = {}

    def _token(self, kind: str, key: str, data: dict[str, Any]) -> str:
        if (kind, key) not in self._by_key:
            number = sum(1 for k, _ in self._by_key if k == kind) + 1
            token = f"{kind}_{number}"
            self._by_key[(kind, key)] = token
            self.entities[token] = {"kind": kind, **data}
        return self._by_key[(kind, key)]

    def asset(self, asset: Asset) -> str:
        return self._token("asset", str(asset.id), {"id": str(asset.id), "name": asset.name})

    def person(self, name: str) -> str:
        return self._token("person", name, {"name": name})


def open_items(session: Session, cve_ids: Sequence[str] | None = None) -> list[Item]:
    query = (
        select(Finding, Asset, Vulnerability)
        .join(Asset, Asset.id == Finding.asset_id)
        .outerjoin(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(Finding.status.in_(ACTIVE_STATUSES))
        .order_by(Finding.risk_score.desc(), Asset.name)
    )
    if cve_ids is not None:
        query = query.where(Vulnerability.cve_id.in_(list(cve_ids)))
    return [Item(f, a, v) for f, a, v in session.execute(query).all()]


def _rank(level: str) -> int:
    return len(LEVEL_ORDER) - LEVEL_ORDER.index(level) if level in LEVEL_ORDER else 0


def light_for(items: Sequence[Item], rules: Sequence[LightRule]) -> LightRule:
    for rule in rules:
        for item in items:
            if rule.min_level is not None and _rank(item.finding.risk_level) < _rank(
                rule.min_level
            ):
                continue
            if rule.in_kev is not None and bool(item.vuln and item.vuln.in_kev) != rule.in_kev:
                continue
            if rule.exposure is not None and item.asset.exposure != rule.exposure:
                continue
            return rule
        if rule.min_level is None and rule.in_kev is None and rule.exposure is None:
            return rule
    return rules[-1]


def deadline(item: Item, config: ReportsConfig, today: date) -> date:
    due = today + timedelta(days=config.fix_within_days.get(item.finding.risk_level, 90))
    if item.vuln is not None and item.vuln.kev_due_date is not None:
        # Termin z KEV bywa już miniony dla starszych wpisów; wtedy liczymy od dziś.
        kev_due = item.vuln.kev_due_date
        if today <= kev_due < due:
            due = kev_due
    return due


def _exposure(asset: Asset) -> str:
    return EXPOSURE.get(asset.exposure, asset.exposure)


def _cve(item: Item) -> str:
    return item.vuln.cve_id if item.vuln else item.finding.type


def _product(item: Item) -> str:
    evidence = item.finding.evidence or {}
    return " ".join(
        filter(None, [str(evidence.get("product") or ""), str(evidence.get("version") or "")])
    )


def _plural(count: int, one: str, few: str, many: str) -> str:
    if count == 1:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def build(
    session: Session,
    config: ReportsConfig,
    *,
    kind: str,
    today: date,
    cve_ids: Sequence[str] | None = None,
) -> ReportData:
    items = open_items(session, cve_ids)
    rule = light_for(items, config.light)
    tokens = Tokens()
    top = items[: config.max_findings_in_summary]
    facts: dict[str, list[str]] = {key: [] for key in QUESTION_KEYS}
    assets = {item.asset.id: item.asset for item in items}
    by_level = {
        level: sum(1 for i in items if i.finding.risk_level == level) for level in LEVEL_ORDER
    }

    # --- Co się stało? ---
    if kind == "zero_day" and cve_ids:
        vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_ids[0]))
        if vuln is not None:
            added = vuln.kev_date_added.isoformat() if vuln.kev_date_added else "dziś"
            facts["what"].append(
                f"Podatność {vuln.cve_id} trafiła do katalogu KEV agencji CISA ({added}): "
                "przestępcy już ją wykorzystują w atakach."
            )
            facts["what"].append(
                f"Ocena powagi CVSS: {vuln.cvss_score if vuln.cvss_score is not None else 'brak'} "
                f"({severity_label(vuln.cvss_score)})."
            )
    else:
        facts["what"].append(
            f"Przegląd objął wszystkie otwarte zagrożenia: {len(items)} "
            f"{_plural(len(items), 'zagrożenie', 'zagrożenia', 'zagrożeń')} na {len(assets)} "
            f"{_plural(len(assets), 'zasobie', 'zasobach', 'zasobach')}."
        )
        facts["what"].append(
            "Według poziomu ryzyka: "
            + ", ".join(f"{level} {count}" for level, count in by_level.items())
            + "."
        )

    # --- Czy jesteśmy zagrożeni? ---
    facts["exposed"].append(f"Ocena systemu: {rule.reason.lower()}.")
    if not items:
        facts["exposed"].append(
            "Żaden zasób w inwentarzu nie ma otwartego zagrożenia w tym zakresie."
        )
    for item in top:
        token = tokens.asset(item.asset)
        facts["exposed"].append(
            f"{token}: {_cve(item)}, poziom ryzyka {item.finding.risk_level} "
            f"({item.finding.risk_score:.0f}/100), zasób {_exposure(item.asset)}, "
            f"ważność zasobu {item.asset.criticality}/5"
            + (
                ", podatność aktywnie wykorzystywana (KEV)"
                if item.vuln and item.vuln.in_kev
                else ""
            )
            + "."
        )
    if len(items) > len(top):
        facts["exposed"].append(
            f"Pozostałe zagrożenia ({len(items) - len(top)}) są w szczegółach technicznych."
        )

    # --- Co najgorszego może się stać? ---
    seen_cves: set[str] = set()
    for item in top:
        if item.vuln is None or item.vuln.cve_id in seen_cves:
            continue
        seen_cves.add(item.vuln.cve_id)
        description = " ".join((item.vuln.description or "").split())[:DESCRIPTION_MAX_CHARS]
        facts["worst"].append(
            f"{item.vuln.cve_id} ({_product(item) or 'oprogramowanie'}): powaga "
            f"{severity_label(item.vuln.cvss_score)}"
            + (", już wykorzystywana przez przestępców" if item.vuln.in_kev else "")
            + (
                f". Opis z rejestru (po angielsku, tylko informacja): {description}"
                if description
                else ""
            )
            + "."
        )
    if not facts["worst"]:
        facts["worst"].append("Brak otwartych podatności, które mogłyby zostać wykorzystane.")

    # --- Co trzeba zrobić? ---
    for item in top:
        token = tokens.asset(item.asset)
        fixed = (item.finding.evidence or {}).get("fixed_version")
        product = _product(item) or "oprogramowanie"
        facts["todo"].append(
            f"{token}: zaktualizować {product} do wersji {fixed} lub nowszej."
            if fixed
            else f"{token}: zastosować poprawkę producenta dla {product}."
        )
    if not top:
        facts["todo"].append("Nie są potrzebne pilne działania; kontynuować regularne skany.")

    # --- Kto i do kiedy? ---
    for item in top:
        token = tokens.asset(item.asset)
        owner = (
            tokens.person(item.asset.owner) if item.asset.owner else "brak właściciela w inwentarzu"
        )
        facts["who"].append(
            f"{token}: odpowiada {owner}, "
            f"termin naprawy {deadline(item, config, today).isoformat()}."
        )
    if not top:
        facts["who"].append("Brak zadań do przypisania.")

    technical = {
        "rows": [
            {
                "asset": tokens.asset(item.asset),
                "cve_id": item.vuln.cve_id if item.vuln else None,
                "product": _product(item),
                "fixed_version": (item.finding.evidence or {}).get("fixed_version"),
                "risk_score": round(item.finding.risk_score, 1),
                "risk_level": item.finding.risk_level,
                "status": item.finding.status,
                "in_kev": bool(item.vuln and item.vuln.in_kev),
                "cvss": item.vuln.cvss_score if item.vuln else None,
                "epss": item.vuln.epss if item.vuln else None,
                "exposure": item.asset.exposure,
                "criticality": item.asset.criticality,
                "deadline": deadline(item, config, today).isoformat(),
                "finding_id": str(item.finding.id),
            }
            for item in items
        ]
    }
    template = _template(kind, rule, items, top, tokens, config, today, cve_ids)
    if kind == "zero_day" and cve_ids:
        title = f"Zero-day: {cve_ids[0]}"
    else:
        title = f"Ocena stanu bezpieczeństwa ({today.isoformat()})"
    return ReportData(
        title=title,
        light=rule.color,
        light_reason=rule.reason,
        facts=facts,
        entities=tokens.entities,
        technical=technical,
        template=template,
        scope={"cve_ids": list(cve_ids)} if cve_ids is not None else {"all_open_findings": True},
    )


def finding_ids(data: ReportData) -> list[uuid.UUID]:
    return [uuid.UUID(row["finding_id"]) for row in data.technical["rows"]]


LEVEL_ADJECTIVE = {
    "krytyczny": "krytyczne",
    "wysoki": "wysokie",
    "średni": "średnie",
    "niski": "niskie",
}


def _template(
    kind: str,
    rule: LightRule,
    items: Sequence[Item],
    top: Sequence[Item],
    tokens: Tokens,
    config: ReportsConfig,
    today: date,
    cve_ids: Sequence[str] | None,
) -> dict[str, str]:
    """Odpowiedzi „W skrócie” budowane przez kod. Przechodzą tę samą walidację co tekst modelu."""
    assets = {item.asset.id for item in items}
    count = len(assets)
    answers: dict[str, str] = {}
    if kind == "zero_day" and cve_ids:
        answers["what"] = (
            f"Podatność {cve_ids[0]} trafiła do katalogu KEV, bo przestępcy już ją wykorzystują. "
            + (
                f"W naszym inwentarzu dotyczy {count} "
                f"{_plural(count, 'zasobu', 'zasobów', 'zasobów')}."
                if count
                else "Nie dotyczy żadnego zasobu w naszym inwentarzu."
            )
        )
    else:
        critical = sum(1 for i in items if i.finding.risk_level == "krytyczny")
        high = sum(1 for i in items if i.finding.risk_level == "wysoki")
        answers["what"] = (
            f"Przegląd objął {len(items)} "
            + _plural(len(items), "otwarte zagrożenie", "otwarte zagrożenia", "otwartych zagrożeń")
            + " "
            f"na {count} {_plural(count, 'zasobie', 'zasobach', 'zasobach')}. "
            f"Krytycznych jest {critical}, wysokich {high}."
        )
    first = top[0] if top else None
    if rule.color == "green" or first is None:
        answers["exposed"] = f"Nie w stopniu wymagającym pilnych działań. {rule.reason}."
    else:
        answers["exposed"] = (
            f"Tak. {rule.reason}. Najpilniejszy jest {tokens.asset(first.asset)}: ryzyko "
            f"{LEVEL_ADJECTIVE.get(first.finding.risk_level, first.finding.risk_level)}, zasób "
            f"{EXPOSURE.get(first.asset.exposure, first.asset.exposure)}."
        )
    worst = next((i for i in top if i.vuln is not None), None)
    if worst is None or worst.vuln is None:
        answers["worst"] = "Nie znaleźliśmy podatności, które można by teraz wykorzystać."
    elif worst.vuln.in_kev:
        answers["worst"] = (
            f"Przestępcy mogą przejąć lub zakłócić {tokens.asset(worst.asset)} przez podatność "
            f"{worst.vuln.cve_id}, której już używają w atakach."
        )
    else:
        answers["worst"] = (
            f"Najpoważniejsza jest podatność {worst.vuln.cve_id} na {tokens.asset(worst.asset)} "
            f"o powadze {severity_label(worst.vuln.cvss_score)}."
        )
    if first is None:
        answers["todo"] = "Nie są potrzebne pilne działania. Wystarczą regularne skany."
    else:
        fixed = (first.finding.evidence or {}).get("fixed_version")
        product = _product(first) or "oprogramowanie"
        answers["todo"] = (
            f"Zaktualizować {product} na {tokens.asset(first.asset)} do wersji {fixed} lub nowszej."
            if fixed
            else f"Zastosować poprawkę producenta dla {product} na {tokens.asset(first.asset)}."
        )
        if len(items) > 1:
            answers["todo"] += " Pozostałe działania są w szczegółach technicznych."
    if first is None:
        answers["who"] = "Nie ma zadań do przypisania ani terminów do pilnowania."
    else:
        parts = []
        # Pierwsze (najwyższe ryzyko, najkrótszy termin) zagrożenie każdego zasobu.
        per_asset: dict[object, Item] = {}
        for item in top:
            per_asset.setdefault(item.asset.id, item)
        for item in list(per_asset.values())[:2]:
            owner = tokens.person(item.asset.owner) if item.asset.owner else "osoba do wskazania"
            parts.append(
                f"Za {tokens.asset(item.asset)} odpowiada {owner}, termin "
                f"{deadline(item, config, today).isoformat()}."
            )
        if len({item.asset.id for item in items}) > 2:
            parts.append("Pozostałe terminy są w szczegółach technicznych.")
        answers["who"] = " ".join(parts)
    return answers
