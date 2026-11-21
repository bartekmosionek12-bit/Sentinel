"""Model organizacji, atrapy źródeł, shadow IT, pokrycie i pseudonimizacja (#18)."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.cli import CliError, cmd_sync_org
from app.core.config import Settings
from app.iam.redaction import REDACTED_PERSON, redact
from app.inventory.service import import_assets, parse_assets_csv
from app.inventory.sources import sources_of
from app.models import (
    Asset,
    AssetAssignment,
    AuditLog,
    CoverageSnapshot,
    Finding,
    Notification,
    OrgUnit,
    Person,
)
from app.models.base import utcnow
from app.org.coverage import as_view, measure, record_snapshot
from app.org.privacy import person_view, pseudonym, record_personal_view
from app.org.shadow import evaluate_shadow
from app.org.sources import OrgSnapshot, collect, demo_sources
from app.org.sync import FIRST_PSEUDONYM, sync_organization
from app.pipeline import Rulebook, analyze
from tests.pipeline_helpers import RULES

ROOT = Path(__file__).resolve().parents[2]
ORG_DIR = ROOT / "demo-lab" / "org"
RULEBOOK = Rulebook.from_dir(RULES)


def _demo_snapshot() -> OrgSnapshot:
    return collect(demo_sources(ORG_DIR))


def _import_csv(session: Session) -> None:
    rows, errors = parse_assets_csv((ROOT / "demo-lab" / "assets.csv").read_text("utf-8"))
    assert not errors
    import_assets(session, rows, source="assets.csv", actor="test")


def _by_name(session: Session, name: str) -> Asset:
    asset = session.scalar(select(Asset).where(Asset.name == name))
    assert asset is not None, name
    return asset


def test_fixtures_are_a_fictional_organization() -> None:
    snapshot = _demo_snapshot()
    roots = [u for u in snapshot.org_units if u.parent is None]
    assert len(roots) == 3  # Dział IT, Finansów, Obsługi Klienta
    assert 20 <= len(snapshot.people) <= 30
    for name in ("ad.json", "mdm.json", "cmdb.json", "dhcp.json"):
        data = json.loads((ORG_DIR / name).read_text("utf-8"))
        assert "Fikcyjna organizacja demo" in data["_note"]
    # Urządzenia spoza CMDB, AD i MDM są tylko w DHCP: to kandydaci na shadow IT.
    known = {d.address for d in snapshot.devices if d.source in ("ad", "mdm", "cmdb") and d.address}
    dhcp_only = {d.address for d in snapshot.devices if d.source == "dhcp"} - known
    assert dhcp_only == {"10.20.0.57", "10.30.0.88"}


def test_sync_merges_sources_into_one_asset_per_device(session: Session) -> None:
    _import_csv(session)
    result = sync_organization(session, _demo_snapshot(), actor="test")
    assert result.people_created == 25
    assert result.org_units == 7
    web = _by_name(session, "web-01")
    # Jeden zasób z CSV i CMDB, bez duplikatu po typie `server`.
    assert session.scalar(select(func.count()).select_from(Asset).where(Asset.name == "web-01"))
    assert sources_of(session, web) == {"csv", "cmdb"}
    unit = session.get(OrgUnit, web.org_unit_id)
    assert unit is not None
    assert unit.name == "Zespół WWW"
    assert web.segment_id is not None
    assert web.location_id is not None
    owner = session.scalar(
        select(AssetAssignment).where(
            AssetAssignment.asset_id == web.id, AssetAssignment.role == "owner"
        )
    )
    assert owner is not None
    # Laptop z AD, MDM i DHCP to jeden zasób po adresie, MAC i nazwie.
    laptop = _by_name(session, "LT-1001")
    assert sources_of(session, laptop) == {"ad", "mdm", "dhcp"}
    assert laptop.attributes["serial"] == "DEMO7001"
    # Ponowna synchronizacja niczego nie dubluje.
    again = sync_organization(session, _demo_snapshot(), actor="test")
    assert again.devices_created == 0
    assert again.people_created == 0
    assert again.assignments_created == 0


def test_pseudonyms_are_stable_and_unique(session: Session) -> None:
    sync_organization(session, _demo_snapshot(), actor="test")
    numbers = {p.external_id: p.pseudonym_no for p in session.scalars(select(Person))}
    assert min(numbers.values()) == FIRST_PSEUDONYM
    assert len(set(numbers.values())) == len(numbers)
    sync_organization(session, _demo_snapshot(), actor="test")
    assert {p.external_id: p.pseudonym_no for p in session.scalars(select(Person))} == numbers


def test_person_missing_from_directory_becomes_inactive_not_deleted(session: Session) -> None:
    snapshot = _demo_snapshot()
    sync_organization(session, snapshot, actor="test")
    gone = snapshot.people[0]
    snapshot.people = snapshot.people[1:]
    result = sync_organization(session, snapshot, actor="test")
    person = session.scalar(select(Person).where(Person.external_id == gone.external_id))
    assert person is not None
    assert not person.active
    assert person.left_at is not None
    assert result.people_left == 1
    # Osoba wyłączona w AD (ostatnia w atrapie) też jest nieaktywna, laptop zostaje przypisany.
    leaver = session.scalar(select(Person).where(Person.external_id == "S-1-5-21-DEMO-1125"))
    assert leaver is not None
    assert not leaver.active


def test_sync_audit_has_counts_but_no_names(session: Session) -> None:
    sync_organization(session, _demo_snapshot(), actor="test")
    entry = session.scalar(select(AuditLog).where(AuditLog.action == "org_synced"))
    assert entry is not None
    dumped = json.dumps(entry.inputs, ensure_ascii=False) + entry.reason
    assert "Kowalczyk" not in dumped
    assert entry.inputs["people_created"] == 25


def test_shadow_rule_flags_network_only_devices_and_notifies(session: Session) -> None:
    _import_csv(session)
    sync_organization(session, _demo_snapshot(), actor="test")
    report = analyze(session, RULEBOOK)
    shadow = {a.name for a in session.scalars(select(Asset).where(Asset.status == "shadow"))}
    assert shadow == {"DESKTOP-7Q2KD1", "kamera-wifi-3f"}
    findings = session.scalars(select(Finding).where(Finding.type == "exposure")).all()
    assert len(findings) == 2
    assert all("CMDB, AD ani MDM" in f.evidence["summary"] for f in findings)
    assert report.summary()["unknown_devices_new"] == 2
    rules = {n.rule_name for n in session.scalars(select(Notification))}
    assert "nieznane_urzadzenie" in rules
    # Drugi przebieg nie tworzy nowych findingów ani powiadomień.
    assert analyze(session, RULEBOOK).summary()["unknown_devices_new"] == 0


def test_shadow_finding_closes_when_device_is_confirmed(session: Session) -> None:
    sync_organization(session, _demo_snapshot(), actor="test")
    evaluate_shadow(session, RULEBOOK.scoring)
    camera = _by_name(session, "kamera-wifi-3f")
    camera.confirmed = True
    changes = evaluate_shadow(session, RULEBOOK.scoring)
    assert [c.kind for c in changes] == ["resolved"]
    assert camera.status == "active"


def test_asset_without_any_source_is_left_alone(session: Session) -> None:
    session.add(Asset(type="host", name="legacy", fingerprint="host:10.0.0.1", attributes={}))
    session.flush()
    assert evaluate_shadow(session, RULEBOOK.scoring) == []


def test_coverage_counts_owner_scan_and_version(session: Session) -> None:
    _import_csv(session)
    sync_organization(session, _demo_snapshot(), actor="test")
    analyze(session, RULEBOOK)
    values = measure(session)
    # 7 hostów z CSV + 25 komputerów z AD + tablet z MDM + 3 z CMDB (drukarka, przełącznik,
    # zapora) + 2 nieznane z DHCP.
    assert values["assets_total"] == 38
    assert values["unknown_devices"] == 2
    assert values["with_owner"] == 36  # wszystko poza dwoma nieznanymi ma dział
    assert values["scanned_recently"] == 0  # nikt jeszcze nie skanował
    row = record_snapshot(session)
    assert as_view(row)["with_owner_pct"] == pytest.approx(94.7)
    # Drugi pomiar tego samego dnia nadpisuje wiersz.
    record_snapshot(session)
    assert session.scalar(select(func.count()).select_from(CoverageSnapshot)) == 1


def test_coverage_scan_window_is_seven_days(session: Session) -> None:
    from app.inventory.sources import touch_source

    asset = Asset(type="host", name="a", fingerprint="host:10.0.0.2", attributes={})
    session.add(asset)
    session.flush()
    touch_source(session, asset, "scan", now=utcnow() - timedelta(days=8))
    assert measure(session)["scanned_recently"] == 0
    touch_source(session, asset, "scan")
    assert measure(session)["scanned_recently"] == 1


def test_pseudonym_views_and_redaction(session: Session) -> None:
    sync_organization(session, _demo_snapshot(), actor="test")
    person = session.scalars(select(Person).order_by(Person.pseudonym_no)).first()
    assert person is not None
    assert pseudonym(person) == f"Pracownik #{FIRST_PSEUDONYM}"
    hidden = person_view(person, show_names=False)
    assert hidden["display_name"] == pseudonym(person)
    assert hidden["job_title"] is None
    shown = person_view(person, show_names=True)
    assert shown["display_name"] == person.full_name
    # Warstwa redakcji: bez `personal_data:view` pseudonim zamiast nazwiska, znacznik dla reszty.
    redacted = redact({"person": shown, "owner": "Zespół WWW"}, technical=False, personal=True)
    assert redacted["person"]["display_name"] == pseudonym(person)
    assert redacted["person"]["job_title"] == REDACTED_PERSON
    assert redacted["owner"] == REDACTED_PERSON


def test_personal_view_audit_lists_ids_without_names(session: Session) -> None:
    sync_organization(session, _demo_snapshot(), actor="test")
    people = list(session.scalars(select(Person)).all())[:3]
    record_personal_view(session, actor="user:manager", people=people, endpoint="/api/org/people")
    session.flush()
    entry = session.scalar(select(AuditLog).where(AuditLog.action == "personal_data_viewed"))
    assert entry is not None
    assert entry.inputs["count"] == 3
    assert all(p.full_name not in json.dumps(entry.inputs, ensure_ascii=False) for p in people)


def test_sync_org_cli_refuses_without_demo_mode(session: Session) -> None:
    with pytest.raises(CliError, match="DEMO_MODE"):
        cmd_sync_org(session, Settings(demo_mode=False))


def test_sync_org_cli_in_demo_mode(session: Session) -> None:
    settings = Settings(demo_mode=True, demo_org_dir=ORG_DIR, rules_dir=RULES)
    result = cmd_sync_org(session, settings)
    assert result["sync"]["people_created"] == 25
    assert result["coverage"]["unknown_devices"] == 2


def test_retention_erases_names_of_people_who_left_long_ago(session: Session) -> None:
    from app.org.privacy import apply_retention

    sync_organization(session, _demo_snapshot(), actor="test")
    leaver = session.scalar(select(Person).where(Person.external_id == "S-1-5-21-DEMO-1125"))
    assert leaver is not None
    assert leaver.left_at is not None
    assert apply_retention(session, days=90) == 0  # odszedł dziś
    assert apply_retention(session, days=90, now=utcnow() + timedelta(days=91)) == 1
    assert leaver.full_name == pseudonym(leaver)
    assert leaver.job_title is None
    # Kolejna synchronizacja z AD (konto nadal wyłączone) nie przywraca nazwiska.
    sync_organization(session, _demo_snapshot(), actor="test")
    assert leaver.full_name == pseudonym(leaver)
    entry = session.scalar(select(AuditLog).where(AuditLog.action == "personal_data_erased"))
    assert entry is not None


def test_demo_coverage_history_is_derived_and_idempotent(session: Session) -> None:
    from app.cli import seed_coverage_history

    sync_organization(session, _demo_snapshot(), actor="test")
    today = record_snapshot(session)
    assert seed_coverage_history(session, today) == 6
    assert seed_coverage_history(session, today) == 0
    rows = session.scalars(select(CoverageSnapshot).order_by(CoverageSnapshot.day)).all()
    assert len(rows) == 7
    assert rows[0].with_owner <= rows[-1].with_owner
