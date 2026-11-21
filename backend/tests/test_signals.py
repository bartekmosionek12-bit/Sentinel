"""Sygnały bez CPE: KEV podaje produkt, NVD jeszcze nie podał zakresu wersji."""

from __future__ import annotations

from datetime import date

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.matching.signals import SignalError, decide_signal
from app.models import AuditLog, Finding, SignalMatch, VulnAffected, Vulnerability
from app.pipeline import Rulebook, analyze
from tests.pipeline_helpers import RULES, SCORING, seed_feeds, seed_inventory

RULEBOOK = Rulebook.from_dir(RULES)
# Fikcyjny identyfikator: nowa podatność w KEV, bez konfiguracji CPE w NVD.
NEW_CVE = "CVE-2099-0001"


def _kev_only(session: Session, vendor: str = "Apache", product: str = "HTTP Server") -> None:
    session.add(
        Vulnerability(
            cve_id=NEW_CVE,
            description="Syntetyczna podatność bez danych o wersjach (test).",
            in_kev=True,
            kev_vendor_project=vendor,
            kev_product=product,
            kev_due_date=date(2099, 1, 10),
            source="kev",
        )
    )
    session.flush()


def _seeded(session: Session) -> None:
    seed_feeds(session)
    seed_inventory(session)
    analyze(session, RULEBOOK)


def _signals(session: Session) -> list[SignalMatch]:
    return list(session.scalars(select(SignalMatch).order_by(SignalMatch.score.desc())))


def test_kev_without_cpe_goes_to_review_and_creates_no_finding(session: Session) -> None:
    _seeded(session)
    findings_before = session.scalars(select(Finding.dedup_key)).all()
    _kev_only(session)
    report = analyze(session, RULEBOOK)
    signals = _signals(session)
    # Oba hosty z Apache httpd (web-01 i legacy-01), nie nginx.
    assert report.signals.created == 2
    # web-01 ma rozpoznane CPE (dowód przez słownik), legacy-01 to pakiet Debiana bez CPE.
    assert signals[0].method == "kev_cpe"
    assert all(s.decision == "pending" and s.score >= RULEBOOK.matching.review for s in signals)
    assert "http_server" in signals[0].reason
    assert session.scalars(select(Finding.dedup_key)).all() == findings_before
    assert "signals_matched" in set(session.scalars(select(AuditLog.action)))
    # Idempotentnie: drugi przebieg nie dubluje sygnałów.
    assert analyze(session, RULEBOOK).signals.created == 0


def test_unrelated_product_is_not_signalled(session: Session) -> None:
    _seeded(session)
    _kev_only(session, vendor="Microsoft", product="Exchange Server")
    assert analyze(session, RULEBOOK).signals.created == 0


def test_human_confirms_signal_then_nvd_range_replaces_it(session: Session) -> None:
    _seeded(session)
    _kev_only(session)
    analyze(session, RULEBOOK)
    accepted, rejected = _signals(session)
    report = decide_signal(session, accepted.id, accept=True, decided_by="admin", scoring=SCORING)
    decide_signal(session, rejected.id, accept=False, decided_by="admin", scoring=SCORING)
    (created,) = report.of_kind("created")
    finding = created.finding
    assert finding.type == "signal"
    assert finding.evidence["version_check"].startswith("brak zakresu wersji")
    assert finding.risk_breakdown["summary"]
    try:
        decide_signal(session, accepted.id, accept=True, decided_by="admin", scoring=SCORING)
    except SignalError:
        pass
    else:  # pragma: no cover
        raise AssertionError("drugi raz nie wolno")

    # NVD dopisuje zakres wersji: zwykłe dopasowanie tworzy finding CVE, sygnał ustępuje.
    vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == NEW_CVE))
    assert vuln is not None
    session.add(
        VulnAffected(
            vulnerability_id=vuln.id,
            cpe_vendor="apache",
            cpe_product="http_server",
            start_including="2.4.0",
            end_excluding="2.4.60",
        )
    )
    session.flush()
    report2 = analyze(session, RULEBOOK)
    assert report2.signals.closed == 1
    session.refresh(finding)
    assert finding.status == "resolved"
    cve = session.scalars(
        select(Finding).where(Finding.type == "cve", Finding.vulnerability_id == vuln.id)
    ).all()
    assert cve


def test_pending_signals_are_superseded_when_nvd_adds_range(session: Session) -> None:
    _seeded(session)
    _kev_only(session)
    analyze(session, RULEBOOK)
    vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == NEW_CVE))
    assert vuln is not None
    session.add(
        VulnAffected(vulnerability_id=vuln.id, cpe_vendor="apache", cpe_product="http_server")
    )
    session.flush()
    assert analyze(session, RULEBOOK).signals.superseded == 2
    assert {s.decision for s in _signals(session)} == {"superseded"}


def test_signal_queue_api(client: TestClient, session: Session) -> None:
    _seeded(session)
    _kev_only(session)
    analyze(session, RULEBOOK)
    session.commit()
    items = client.get("/api/signal-queue").json()
    assert len(items) == 2
    assert items[0]["cve_id"] == NEW_CVE
    assert items[0]["kev_due_date"] == "2099-01-10"
    decided = client.post(f"/api/signal-queue/{items[0]['id']}/decision", json={"accept": True})
    assert decided.status_code == 200, decided.text
    assert decided.json() == {"decision": "confirmed", "findings_created": 1}
    again = client.post(f"/api/signal-queue/{items[0]['id']}/decision", json={"accept": True})
    assert again.status_code == 409
    assert len(client.get("/api/signal-queue").json()) == 1
