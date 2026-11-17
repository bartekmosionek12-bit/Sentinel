"""Wyjaśnienie z szablonu: zbudowane przez kod wyłącznie z danych z bazy.

Pokazywane z etykietą „wersja automatyczna”, gdy model jest wyłączony, niedostępny
albo jego odpowiedź nie przeszła walidacji. Dzięki temu system jest w pełni użyteczny
bez modelu.
"""

from __future__ import annotations

from app.explainer.context import ExplainContext


def _products(context: ExplainContext) -> str:
    titles = [p.title for p in context.products]
    if not titles:
        return "oprogramowaniu wskazanym w zagrożeniu"
    return titles[0] if len(titles) == 1 else ", ".join(titles[:-1]) + " i " + titles[-1]


def _fix(context: ExplainContext) -> str:
    fixes = [
        f"{p.title} do wersji {p.fixed_version} lub nowszej"
        for p in context.products
        if p.fixed_version
    ]
    if fixes:
        return "Zaktualizuj " + "; ".join(fixes) + "."
    return "Zaktualizuj oprogramowanie do najnowszej wersji wskazanej przez producenta."


def _urgency(context: ExplainContext) -> str:
    if context.in_kev:
        due = (
            f" Termin usunięcia wg CISA KEV: {context.kev_due_date.isoformat()}."
            if context.kev_due_date
            else ""
        )
        return "Podatność jest aktywnie wykorzystywana w atakach (katalog CISA KEV)." + due
    if context.has_public_exploit:
        return "Istnieje publicznie dostępny exploit, choć katalog CISA KEV nie potwierdza ataków."
    return "Katalog CISA KEV nie potwierdza wykorzystania tej podatności w atakach."


def _cvss(context: ExplainContext) -> str:
    if context.cvss_score is None:
        return "waga nie została jeszcze oceniona w CVSS"
    return f"waga {context.severity} (CVSS {context.cvss_score:.1f} na 10)"


def render_fallback(context: ExplainContext, audience: str) -> str:
    products = _products(context)
    if audience == "executive":
        risk = (
            "jest już wykorzystywana przez atakujących"
            if context.in_kev
            else f"ma wagę ocenioną jako {context.severity}"
        )
        return (
            f"W używanym u nas oprogramowaniu ({products}) wykryto podatność {context.cve_id}, "
            f"która {risk}. Potrzebna jest aktualizacja tego oprogramowania"
            + (
                f" do {context.kev_due_date.isoformat()}."
                if context.in_kev and context.kev_due_date
                else "."
            )
        )
    if audience == "operational":
        return (
            f"Podatność {context.cve_id} dotyczy: {products}; {_cvss(context)}. "
            f"{_urgency(context)} {_fix(context)}"
        )
    ranges = "; ".join(f"{p.title}: {', '.join(p.ranges)}" for p in context.products)
    check = (
        "Sprawdź zainstalowaną wersję poleceniem "
        + " albo ".join(f"`{c}`" for c in context.commands)
        + " i porównaj ją z wersją naprawiającą."
        if context.commands
        else "Sprawdź zainstalowaną wersję w menedżerze pakietów i porównaj ją "
        "z wersją naprawiającą."
    )
    action = (
        f" Działanie wymagane wg CISA KEV: {context.kev_required_action}"
        if context.kev_required_action
        else ""
    )
    return (
        f"Co to jest:\nPodatność {context.cve_id}, {_cvss(context)}. "
        f"Podatne wersje: {ranges or 'brak danych o zakresie wersji'}. {_urgency(context)}\n\n"
        f"Co zrobić:\n{_fix(context)}{action}\n\n"
        f"Jak sprawdzić:\n{check}"
    )
