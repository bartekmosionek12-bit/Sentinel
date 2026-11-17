"""Matching Engine: progi pewności, kolejka weryfikacji, findingi i ich cykl życia."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.inventory.service import record_host_scan
from app.matching.engine import (
    CandidateError,
    build_normalizer,
    decide_candidate,
    evaluate_findings,
    resolve_products,
)
from app.models import (
    AuditLog,
    Finding,
    FindingEvent,
    MatchCandidate,
    Software,
    Vulnerability,
)
from app.scanners.models import HostScan, ServiceInfo
from tests.pipeline_helpers import (
    ALIASES,
    MATCHING,
    SCORING,
    asset_by_ip,
    seed_feeds,
    seed_inventory,
)


@pytest.fixture
def seeded(session: Session) -> Session:
    seed_feeds(session)
    seed_inventory(session)
    return session


def _resolve(session: Session) -> None:
    resolve_products(session, build_normalizer(session, ALIASES), MATCHING)


def _software(session: Session, ip: str, port: int) -> Software:
    asset = asset_by_ip(session, ip)
    software = session.scalar(
        select(Software).where(Software.asset_id == asset.id, Software.port == port)
    )
    assert software is not None
    return software


def _findings(session: Session, ip: str) -> dict[str, Finding]:
    asset = asset_by_ip(session, ip)
    rows = session.execute(
        select(Vulnerability.cve_id, Finding)
        .join(Finding, Finding.vulnerability_id == Vulnerability.id)
        .where(Finding.asset_id == asset.id)
    ).all()
    return {cve_id: finding for cve_id, finding in rows}


def test_products_are_resolved_by_alias_distro_penalty_and_unknown(seeded: Session) -> None:
    _resolve(seeded)
    apache = _software(seeded, "172.30.99.10", 80)
    assert (apache.match_status, apache.match_method, apache.match_confidence) == (
        "auto",
        "alias",
        1.0,
    )
    assert (apache.cpe_vendor, apache.cpe_product) == ("apache", "http_server")
    # nmap podaje historyczne CPE igor_sysoev:nginx, alias prowadzi do f5:nginx z NVD
    nginx = _software(seeded, "172.30.99.11", 80)
    assert (nginx.match_status, nginx.cpe_vendor) == ("auto", "f5")

    debian = _software(seeded, "172.30.99.12", 80)
    assert (debian.match_status, debian.match_confidence) == ("needs_review", 0.7)
    assert debian.cpe_product is None
    candidate = seeded.scalar(select(MatchCandidate).where(MatchCandidate.software_id == debian.id))
    assert candidate is not None
    assert candidate.cpe == "cpe:2.3:a:apache:http_server"
    assert "pakiet dystrybucji" in candidate.reason

    unknown = _software(seeded, "172.30.99.12", 3000)
    assert (unknown.match_status, unknown.match_method) == ("unmatched", "none")
    assert "products_matched" in seeded.scalars(select(AuditLog.action)).all()


def test_fuzzy_match_below_auto_threshold_goes_to_review(seeded: Session) -> None:
    asset = asset_by_ip(seeded, "172.30.99.11")
    record_host_scan(
        seeded,
        asset,
        HostScan(
            ip="172.30.99.11",
            services=(ServiceInfo(8080, "tcp", "http", "Apache Log4j logging", "2.14.1"),),
        ),
    )
    _resolve(seeded)
    software = _software(seeded, "172.30.99.11", 8080)
    assert software.match_method == "fuzzy"
    assert software.match_status == "needs_review"
    assert MATCHING.review <= software.match_confidence < MATCHING.auto
    evaluate_findings(seeded, SCORING)
    assert _findings(seeded, "172.30.99.11") == {}


def test_findings_are_created_only_for_versions_in_range(seeded: Session) -> None:
    _resolve(seeded)
    report = evaluate_findings(seeded, SCORING)

    web = _findings(seeded, "172.30.99.10")
    assert set(web) == {"CVE-2021-41773", "CVE-2021-42013"}
    traversal = web["CVE-2021-41773"]
    assert (traversal.risk_score, traversal.risk_level) == (91.9, "krytyczny")
    assert traversal.risk_breakdown["summary"].startswith("Krytyczny, bo: ")
    assert traversal.evidence["affected_range"] == "= 2.4.49"
    assert traversal.evidence["version"] == "2.4.49"

    proxy = _findings(seeded, "172.30.99.11")
    assert set(proxy) == {"CVE-2021-23017"}
    assert proxy["CVE-2021-23017"].evidence["fixed_version"] == "1.20.1"
    assert proxy["CVE-2021-23017"].risk_level == "niski"
    # dopasowanie w kolejce weryfikacji nie tworzy findingów
    assert _findings(seeded, "172.30.99.12") == {}

    assert len(report.of_kind("created")) == 3
    events = seeded.scalars(select(FindingEvent.kind)).all()
    assert events == ["created"] * 3
    assert seeded.scalars(select(AuditLog.action)).all().count("finding_created") == 3


def test_evaluation_is_idempotent(seeded: Session) -> None:
    _resolve(seeded)
    evaluate_findings(seeded, SCORING)
    again = evaluate_findings(seeded, SCORING)
    assert again.changes == []
    assert seeded.scalar(select(func.count()).select_from(Finding)) == 3
    assert seeded.scalar(select(func.count()).select_from(FindingEvent)) == 3


def test_accepting_a_candidate_creates_findings_and_rejecting_does_not(seeded: Session) -> None:
    _resolve(seeded)
    debian = _software(seeded, "172.30.99.12", 80)
    candidate = seeded.scalar(select(MatchCandidate).where(MatchCandidate.software_id == debian.id))
    assert candidate is not None
    decide_candidate(seeded, candidate.id, accept=True, decided_by="anna")
    assert (debian.match_status, debian.cpe_product) == ("confirmed", "http_server")
    assert (candidate.decision, candidate.decided_by) == ("accepted", "anna")
    evaluate_findings(seeded, SCORING)
    assert set(_findings(seeded, "172.30.99.12")) == {
        "CVE-2017-9798",
        "CVE-2019-0211",
        "CVE-2021-40438",
    }
    assert "match_confirmed" in seeded.scalars(select(AuditLog.action)).all()
    with pytest.raises(CandidateError, match="już rozstrzygnięty"):
        decide_candidate(seeded, candidate.id, accept=False, decided_by="anna")
    with pytest.raises(CandidateError, match="Nie znaleziono"):
        decide_candidate(seeded, uuid.uuid4(), accept=True, decided_by="anna")


def test_rejecting_the_only_candidate_marks_software_rejected(seeded: Session) -> None:
    _resolve(seeded)
    debian = _software(seeded, "172.30.99.12", 80)
    candidate = seeded.scalar(select(MatchCandidate).where(MatchCandidate.software_id == debian.id))
    assert candidate is not None
    decide_candidate(seeded, candidate.id, accept=False, decided_by="anna")
    assert debian.match_status == "rejected"
    evaluate_findings(seeded, SCORING)
    assert _findings(seeded, "172.30.99.12") == {}
    # ponowne rozstrzyganie nie wraca do odrzuconego dopasowania
    _resolve(seeded)
    assert debian.match_status == "rejected"


def test_unknown_version_never_creates_a_finding(seeded: Session) -> None:
    asset = asset_by_ip(seeded, "172.30.99.11")
    record_host_scan(
        seeded,
        asset,
        HostScan(ip="172.30.99.11", services=(ServiceInfo(80, "tcp", "http", "nginx", ""),)),
    )
    _resolve(seeded)
    report = evaluate_findings(seeded, SCORING)
    assert _findings(seeded, "172.30.99.11") == {}
    assert report.undetermined == 1


def test_upgrade_resolves_finding_and_downgrade_reopens_it(seeded: Session) -> None:
    _resolve(seeded)
    evaluate_findings(seeded, SCORING)
    web = asset_by_ip(seeded, "172.30.99.10")

    def scan(version: str) -> None:
        record_host_scan(
            seeded,
            web,
            HostScan(
                ip="172.30.99.10",
                services=(ServiceInfo(80, "tcp", "http", "Apache httpd", version),),
            ),
        )
        _resolve(seeded)

    scan("2.4.62")
    report = evaluate_findings(seeded, SCORING)
    assert len(report.of_kind("resolved")) == 2
    assert {f.status for f in _findings(seeded, "172.30.99.10").values()} == {"resolved"}

    scan("2.4.50")
    report = evaluate_findings(seeded, SCORING)
    reopened = report.of_kind("reopened")
    assert len(reopened) == 1
    findings = _findings(seeded, "172.30.99.10")
    assert findings["CVE-2021-42013"].status == "open"
    assert findings["CVE-2021-41773"].status == "resolved"
    assert seeded.scalar(select(func.count()).select_from(Finding)) == 3


def test_closed_by_human_stays_closed(seeded: Session) -> None:
    _resolve(seeded)
    evaluate_findings(seeded, SCORING)
    finding = _findings(seeded, "172.30.99.10")["CVE-2021-41773"]
    finding.status = "accepted_risk"
    seeded.flush()
    report = evaluate_findings(seeded, SCORING)
    assert report.changes == []
    assert finding.status == "accepted_risk"


def test_new_threat_intel_rescores_with_an_explained_reason(seeded: Session) -> None:
    _resolve(seeded)
    evaluate_findings(seeded, SCORING)
    finding = _findings(seeded, "172.30.99.11")["CVE-2021-23017"]
    before = finding.risk_score
    vuln = seeded.scalar(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2021-23017"))
    assert vuln is not None
    vuln.in_kev = True
    seeded.flush()

    report = evaluate_findings(seeded, SCORING)
    (change,) = report.of_kind("rescored")
    assert change.finding.id == finding.id
    assert finding.risk_score == pytest.approx(before + 20.0)
    event = seeded.scalars(select(FindingEvent).where(FindingEvent.kind == "rescored")).one()
    assert event.reason == "Aktywnie wykorzystywana (KEV): poza KEV → w katalogu KEV"
    assert event.before["score"] == before
    assert event.after["score"] == finding.risk_score
