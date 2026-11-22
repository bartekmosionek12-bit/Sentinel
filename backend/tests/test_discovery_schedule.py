"""Harmonogram discovery: okno czasowe, częstotliwość, wstrzymanie i wznowienie przebiegu."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.audit import DbAuditSink
from app.core.scope_guard import ScopeConfig, ScopeGuard
from app.discovery.engine import DiscoveryConfig, DiscoveryEngine
from app.discovery.schedule import current_window, next_start, tick
from app.models import AuditLog, DiscoveryRun, DiscoverySchedule
from app.scanners.models import ServiceInfo
from app.scanners.nmap import NmapAdapter
from tests.conftest import FakeResolver, RecordingDispatcher
from tests.scanner_fakes import FakeLab

RULES = Path(__file__).resolve().parents[2] / "rules" / "discovery.yaml"
CONFIG = DiscoveryConfig.from_file(RULES)
# Niedziela 22.11.2026, 23:00 w Warszawie (UTC+1).
SUNDAY_23 = datetime(2026, 11, 22, 22, 0, tzinfo=UTC)


def _schedule(**kwargs: Any) -> DiscoverySchedule:
    values: dict[str, Any] = {
        "name": "noc",
        "targets": ["10.10.0.0/24"],
        "settings": {"workers": 1},
        "interval_minutes": 1440,
        "window_start": "22:00",
        "window_end": "06:00",
        "days": list(range(7)),
        "timezone": "Europe/Warsaw",
        "enabled": True,
        "created_by": "user:admin",
    }
    values.update(kwargs)
    return DiscoverySchedule(**values)


def test_window_across_midnight_and_days() -> None:
    schedule = _schedule(days=[6])  # tylko niedziela
    window = current_window(schedule, SUNDAY_23)
    assert window is not None
    assert window.end == datetime(2026, 11, 23, 5, 0, tzinfo=UTC)  # poniedziałek 06:00 lokalnie
    # Poniedziałek 03:00 lokalnie: okno zaczęte w niedzielę nadal trwa.
    assert current_window(schedule, SUNDAY_23 + timedelta(hours=4)) is not None
    # Poniedziałek 07:00 lokalnie: poza oknem, następny start dopiero w niedzielę 22:00.
    monday_morning = SUNDAY_23 + timedelta(hours=8)
    assert current_window(schedule, monday_morning) is None
    assert next_start(schedule, monday_morning) == datetime(2026, 11, 29, 21, 0, tzinfo=UTC)


def _engine(factory: sessionmaker[Session], lab: FakeLab) -> tuple[ScopeGuard, NmapAdapter]:
    guard = ScopeGuard(
        ScopeConfig.from_dict({"allow": {"cidrs": ["10.10.0.0/24"]}}),
        audit=DbAuditSink(factory),
        resolver=FakeResolver(),
    )
    return guard, NmapAdapter(lab.runner)


def test_tick_starts_pauses_at_window_end_and_resumes(
    session_factory: sessionmaker[Session],
) -> None:
    lab = FakeLab({"10.10.0.5": [ServiceInfo(port=80, protocol="tcp", name="http")]})
    guard, nmap = _engine(session_factory, lab)
    dispatcher = RecordingDispatcher()
    with session_factory() as session:
        session.add(_schedule())
        session.commit()
        # Poza oknem (Warszawa 12:00) nic nie startuje.
        assert tick(session, CONFIG, dispatcher, SUNDAY_23 - timedelta(hours=11)) == []
        [run] = tick(session, CONFIG, dispatcher, SUNDAY_23)
        assert run.deadline is not None
        assert run.schedule_id is not None
        # Drugi tick w tym samym oknie: przebieg trwa albo częstotliwość jeszcze nie minęła.
        assert tick(session, CONFIG, dispatcher, SUNDAY_23 + timedelta(minutes=1)) == []
        # Symulujemy przebieg dłuższy niż okno: termin minął, zanim silnik wziął paczkę.
        run.deadline = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
        run_id = run.id
    with session_factory() as session:
        paused = DiscoveryEngine(session, guard, CONFIG, nmap=nmap).run(run_id)
        assert paused.status == "paused"
        assert paused.remaining == {"networks": ["10.10.0.0/24"], "hosts": []}
        assert paused.summary["window_closed"] is True
        schedule = session.scalars(select(DiscoverySchedule)).one()
        assert schedule.resume_run_id == run_id
    with session_factory() as session:
        # Kolejne okno (poniedziałek 22:00 lokalnie): wznowienie zamiast nowego przebiegu.
        [resumed] = tick(session, CONFIG, dispatcher, SUNDAY_23 + timedelta(days=1))
        assert resumed.resume_of == run_id
        assert resumed.targets == ["10.10.0.0/24"]
        assert "wznowienie" in resumed.name
        resumed_id = resumed.id
    with session_factory() as session:
        done = DiscoveryEngine(session, guard, CONFIG, nmap=nmap).run(resumed_id)
        assert done.status == "done"
        assert done.hosts_up == 1
        actions = set(session.scalars(select(AuditLog.action)))
        assert {"discovery_requested", "discovery_finished"} <= actions


def test_schedule_api_and_permissions(
    client: TestClient, anon_client: TestClient, tokens: Any
) -> None:
    created = client.post(
        "/api/discovery/schedules",
        json={
            "name": "Nocny skan labu",
            "items": ["10.10.0.0/24"],
            "interval_minutes": 1440,
            "window_start": "22:00",
            "window_end": "06:00",
            "days": [0, 1, 2, 3, 4],
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["next_start_at"] is not None
    assert body["days"] == [0, 1, 2, 3, 4]
    bad = client.post(
        "/api/discovery/schedules",
        json={"name": "x", "items": ["10.10.0.0/24"], "window_start": "25:00"},
    )
    assert bad.status_code == 422
    too_often = client.post(
        "/api/discovery/schedules",
        json={"name": "x", "items": ["10.10.0.0/24"], "interval_minutes": 5},
    )
    assert too_often.status_code == 422
    schedule_id = body["id"]
    updated = client.put(
        f"/api/discovery/schedules/{schedule_id}",
        json={"name": "Nocny skan labu", "items": ["10.10.0.0/24"], "enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["next_start_at"] is None
    assert len(client.get("/api/discovery/schedules").json()) == 1

    viewer = tokens.headers(["viewer"], username="v")
    assert anon_client.get("/api/discovery/schedules", headers=viewer).status_code == 200
    denied = anon_client.post(
        "/api/discovery/schedules",
        headers=viewer,
        json={"name": "x", "items": ["10.10.0.0/24"]},
    )
    assert denied.status_code == 403
    assert client.delete(f"/api/discovery/schedules/{schedule_id}").status_code == 204
    assert client.get("/api/discovery/schedules").json() == []


def test_paused_run_does_not_count_as_miss(session_factory: sessionmaker[Session]) -> None:
    from app.discovery.analysis import host_states
    from app.models import Observation

    with session_factory() as session:
        start = datetime(2026, 11, 20, tzinfo=UTC)
        for index, status in enumerate(("done", "done", "paused", "paused")):
            run = DiscoveryRun(
                name=str(index),
                status=status,
                targets=["10.10.0.0/24"],
                created_at=start + timedelta(hours=index),
            )
            session.add(run)
            session.flush()
            if status == "done":
                session.add(Observation(run_id=run.id, ip="10.10.0.5"))
        session.commit()
        assert host_states(session)["10.10.0.5"]["state"] == "active"


class FlakyLab(FakeLab):
    """Host 10.10.0.7 nie odpowiada na sweep całej paczki, ale odpowiada na ponowną próbę /32."""

    def _respond(self, argv: tuple[str, ...]) -> str:
        from tests.scanner_fakes import discovery_xml

        if "-sn" in argv and argv[-1].endswith("/24"):
            return discovery_xml(sorted(ip for ip in self.services if ip != "10.10.0.7"))
        return super()._respond(argv)


def test_missing_host_gets_a_second_probe(session_factory: sessionmaker[Session]) -> None:
    services = {
        "10.10.0.5": [ServiceInfo(port=80, protocol="tcp", name="http")],
        "10.10.0.7": [ServiceInfo(port=22, protocol="tcp", name="ssh")],
    }
    stable = FakeLab(services)
    flaky = FlakyLab(services)
    from app.discovery.schedule import new_run

    ids = []
    for lab in (stable, flaky):
        guard, nmap = _engine(session_factory, lab)
        with session_factory() as session:
            run = new_run(
                session,
                CONFIG,
                ["10.10.0.0/24"],
                name="r",
                settings={"workers": 1},
                actor="t",
            )
            session.commit()
            run_id = run.id
        with session_factory() as session:
            done = DiscoveryEngine(session, guard, CONFIG, nmap=nmap).run(run_id)
            ids.append(done.id)
            summary = dict(done.summary)
    assert summary["retried"] == 1
    assert summary["recovered_on_retry"] == 1
    with session_factory() as session:
        from app.models import Observation

        ips = set(session.scalars(select(Observation.ip).where(Observation.run_id == ids[1])))
        assert ips == {"10.10.0.5", "10.10.0.7"}
    assert any("10.10.0.7/32" in " ".join(c) for c in flaky.runner.calls)


def test_time_of_day_pattern() -> None:
    from app.discovery.analysis import time_profile

    noon = datetime(2026, 11, 20, 11, tzinfo=UTC)  # 12:00 w Warszawie
    midnight = datetime(2026, 11, 20, 23, tzinfo=UTC)  # 00:00 w Warszawie
    samples = [
        (noon, True),
        (noon + timedelta(days=1), True),
        (midnight, False),
        (midnight + timedelta(days=1), False),
    ]
    profile = time_profile(samples)
    assert profile["pattern"] == "day_only"
    assert profile["label"] == "odpowiada tylko w dzień"
    assert time_profile(samples[:3])["pattern"] is None  # za mało pomiarów nocą
