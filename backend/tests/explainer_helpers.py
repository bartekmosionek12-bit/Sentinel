"""Wspólne dane do testów explainera: baza z findingami demo i poprawne odpowiedzi modelu."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.explainer.context import ExplainerConfig, product_titles
from app.matching.engine import build_normalizer, evaluate_findings, resolve_products
from app.models import Vulnerability
from tests.pipeline_helpers import ALIASES, MATCHING, RULES, SCORING, seed_feeds, seed_inventory

CONFIG = ExplainerConfig.from_file(RULES / "explainer.yaml")
TITLES = product_titles(ALIASES)
CVE = "CVE-2021-41773"

GOOD = {
    "executive": (
        "W naszym serwerze Apache HTTP Server jest podatność, która jest już wykorzystywana "
        "przez atakujących i zagraża ciągłości działania firmy. Należy pilnie zaktualizować "
        "to oprogramowanie do najnowszej wersji wskazanej przez producenta."
    ),
    "operational": (
        "Podatność CVE-2021-41773 dotyczy serwera Apache HTTP Server w wersji 2.4.49 i jest "
        "aktywnie wykorzystywana w atakach, co potwierdza katalog CISA KEV. Sprawa jest pilna, "
        "ponieważ istnieje publicznie dostępny exploit. Zespół powinien zaktualizować serwer do "
        "najnowszej wersji wskazanej przez producenta w terminie do 2021-11-17."
    ),
    "technical": (
        "Co to jest:\nPodatność CVE-2021-41773 w Apache HTTP Server pozwala na odczyt plików "
        "spoza katalogu serwera. Dotyczy wyłącznie wersji 2.4.49 i jest wykorzystywana "
        "w atakach.\n\n"
        "Co zrobić:\nNależy zaktualizować serwer do najnowszej wersji wskazanej przez producenta. "
        "Do czasu aktualizacji warto ograniczyć dostęp do serwera z internetu.\n\n"
        "Jak sprawdzić:\nZainstalowaną wersję pokaże polecenie `httpd -v` albo `apache2 -v`."
    ),
}


def seed_findings(session: Session) -> None:
    seed_feeds(session)
    seed_inventory(session)
    resolve_products(session, build_normalizer(session, ALIASES), MATCHING)
    evaluate_findings(session, SCORING)
    session.flush()


def vulnerability(session: Session, cve_id: str = CVE) -> Vulnerability:
    vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    assert vuln is not None
    return vuln
