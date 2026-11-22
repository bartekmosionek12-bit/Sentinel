"""Harmonogram discovery (brief, sekcja 2): częstotliwość, okno czasowe, wznowienie.

Co minutę beat woła `tick`. Dla każdego włączonego harmonogramu:

1. trwa jego przebieg → nic nie robimy,
2. teraz jest poza oknem → czekamy,
3. jest wstrzymany przebieg (przekroczył poprzednie okno) → startuje wznowienie, czyli nowy
   przebieg z niezeskanowaną resztą celów i terminem końca bieżącego okna,
4. minęła częstotliwość od ostatniego startu → startuje nowy przebieg z terminem końca okna.

Harmonogram jednorazowy (`start_at`, `end_at`) ma jedno okno: od startu do końca. Przebieg
rusza o `start_at`; jeśli nie skończy przed `end_at`, kończy rozpoczęte paczki, zapisuje
niezeskanowaną resztę (status „paused”) i czeka na „Wznów” w konsoli.

Przebieg tworzy ta sama funkcja co w konsoli (`new_run`): ta sama walidacja celów, limity
i audyt; każdy cel i tak przechodzi przez scope_guard w silniku.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from typing import Any, Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.discovery.engine import DiscoveryConfig, parse_targets
from app.models import DiscoveryRun, DiscoverySchedule
from app.models.base import utcnow

ACTIVE = ("queued", "running", "stopping")
_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
MIN_INTERVAL = 15
DAY_NAMES = ("pon", "wt", "śr", "czw", "pt", "sob", "nd")


class RunDispatcher(Protocol):
    def run_discovery(self, run_id: Any) -> str: ...


class RunError(ValueError):
    """Przebieg nie może wystartować (złe cele, przekroczony limit adresów)."""


def aware(moment: datetime | None) -> datetime | None:
    """SQLite oddaje daty bez strefy; w bazie zawsze zapisujemy UTC."""
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def new_run(
    session: Session,
    config: DiscoveryConfig,
    items: list[str],
    *,
    name: str,
    settings: dict[str, Any],
    actor: str,
    reason: str = "Zlecono przebieg discovery",
    schedule: DiscoverySchedule | None = None,
    deadline: datetime | None = None,
    resume_of: DiscoveryRun | None = None,
) -> DiscoveryRun:
    parsed = parse_targets(items)
    if parsed.errors:
        raise RunError("; ".join(parsed.errors[:5]))
    if not parsed.networks and not parsed.domains:
        raise RunError("Podaj co najmniej jeden cel")
    limit = config.limits.get("addresses", 70000)
    if parsed.addresses > limit:
        raise RunError(f"Za dużo adresów ({parsed.addresses}, limit {limit})")
    resolved = config.settings(settings)
    run = DiscoveryRun(
        name=name or f"Przebieg {utcnow():%Y-%m-%d %H:%M}",
        targets=[*map(str, parsed.networks), *parsed.domains],
        settings={**resolved.__dict__, "http_paths": list(resolved.http_paths)},
        created_by=actor,
        addresses_total=parsed.addresses,
        schedule_id=schedule.id if schedule else None,
        deadline=deadline,
        resume_of=resume_of.id if resume_of else None,
    )
    session.add(run)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="discovery_requested",
            reason=reason,
            inputs={
                "targets": run.targets[:50],
                "addresses": parsed.addresses,
                "settings": run.settings,
                "schedule": str(schedule.id) if schedule else None,
                "deadline": deadline.isoformat() if deadline else None,
                "resume_of": str(resume_of.id) if resume_of else None,
            },
            object_type="discovery_run",
            object_id=str(run.id),
        ),
    )
    return run


# --- okno czasowe --------------------------------------------------------------------


def validate(window_start: str, window_end: str, days: list[int], tz: str, interval: int) -> None:
    for value in (window_start, window_end):
        if not _HHMM.match(value):
            raise RunError(f"Godzina „{value}” nie ma postaci HH:MM")
    if not days or any(d not in range(7) for d in days):
        raise RunError("Wybierz co najmniej jeden dzień tygodnia")
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise RunError(f"Nieznana strefa czasowa „{tz}”") from error
    if interval < MIN_INTERVAL:
        raise RunError(f"Częstotliwość co najmniej co {MIN_INTERVAL} minut")


def validate_once(start_at: datetime, end_at: datetime, now: datetime) -> None:
    start = start_at if start_at.tzinfo else start_at.replace(tzinfo=UTC)
    end = end_at if end_at.tzinfo else end_at.replace(tzinfo=UTC)
    if end <= start:
        raise RunError("Koniec skanu musi być później niż jego początek")
    if end <= now:
        raise RunError("Koniec skanu już minął")


def _hhmm(value: str) -> time:
    hour, minute = value.split(":")
    return time(int(hour), int(minute))


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime


def _window_from(day: datetime, schedule: DiscoverySchedule, zone: ZoneInfo) -> Window:
    start_t, end_t = _hhmm(schedule.window_start), _hhmm(schedule.window_end)
    start = datetime.combine(day.date(), start_t, tzinfo=zone)
    end = datetime.combine(day.date(), end_t, tzinfo=zone)
    if end <= start:  # okno przez północ, np. 22:00–06:00
        end += timedelta(days=1)
    return Window(start.astimezone(UTC), end.astimezone(UTC))


def _once_bounds(schedule: DiscoverySchedule) -> tuple[datetime, datetime]:
    start, end = aware(schedule.start_at), aware(schedule.end_at)
    if start is None or end is None:
        raise RunError("Skan jednorazowy wymaga początku i końca")
    return start, end


def current_window(schedule: DiscoverySchedule, now: datetime) -> Window | None:
    """Okno, w którym jest `now` (okno zaczęte wczoraj też się liczy, gdy trwa przez północ)."""
    if schedule.once:
        start, end = _once_bounds(schedule)
        return Window(start, end) if start <= now < end else None
    zone = ZoneInfo(schedule.timezone)
    local = now.astimezone(zone)
    for back in (0, 1):
        day = local - timedelta(days=back)
        if day.weekday() not in schedule.days:
            continue
        window = _window_from(day, schedule, zone)
        if window.start <= now < window.end:
            return window
    return None


def next_window(schedule: DiscoverySchedule, now: datetime) -> Window | None:
    current = current_window(schedule, now)
    if current is not None:
        return current
    if schedule.once:
        start, end = _once_bounds(schedule)
        return Window(start, end) if now < start else None
    zone = ZoneInfo(schedule.timezone)
    local = now.astimezone(zone)
    for ahead in range(8):
        day = local + timedelta(days=ahead)
        if day.weekday() not in schedule.days:
            continue
        window = _window_from(day, schedule, zone)
        if window.start > now:
            return window
    return None


def next_start(schedule: DiscoverySchedule, now: datetime) -> datetime | None:
    """Najbliższa chwila, w której `tick` wystartuje przebieg (do pokazania w konsoli)."""
    if not schedule.enabled:
        return None
    if schedule.once:
        if schedule.last_started_at is not None:
            return None
        window = next_window(schedule, now)
        return max(now, window.start) if window else None
    due = aware(schedule.last_started_at)
    due = now if due is None else max(now, due + timedelta(minutes=schedule.interval_minutes))
    if schedule.resume_run_id is not None:
        due = now
    for _ in range(64):
        window = current_window(schedule, due)
        if window is not None:
            return due
        upcoming = next_window(schedule, due)
        if upcoming is None:
            return None
        due = upcoming.start
    return None


# --- tick ----------------------------------------------------------------------------


def tick(
    session: Session,
    config: DiscoveryConfig,
    dispatcher: RunDispatcher,
    now: datetime | None = None,
) -> list[DiscoveryRun]:
    now = now or utcnow()
    started: list[DiscoveryRun] = []
    for schedule in session.scalars(
        select(DiscoverySchedule).where(DiscoverySchedule.enabled.is_(True))
    ):
        busy = session.scalar(
            select(DiscoveryRun.id)
            .where(DiscoveryRun.schedule_id == schedule.id, DiscoveryRun.status.in_(ACTIVE))
            .limit(1)
        )
        if busy is not None:
            continue
        window = current_window(schedule, now)
        if window is None:
            continue
        run: DiscoveryRun | None = None
        try:
            paused = (
                session.get(DiscoveryRun, schedule.resume_run_id)
                if schedule.resume_run_id
                else None
            )
            if paused is not None and paused.remaining:
                rest = [*paused.remaining.get("networks", []), *paused.remaining.get("hosts", [])]
                base = paused.name.split(" (wznowienie")[0]
                run = new_run(
                    session,
                    config,
                    rest,
                    name=f"{base} (wznowienie {now:%d.%m %H:%M})",
                    settings=schedule.settings,
                    actor=f"system:schedule:{schedule.name}"[:255],
                    reason="Wznowienie przebiegu przerwanego na końcu okna czasowego",
                    schedule=schedule,
                    deadline=window.end,
                    resume_of=paused,
                )
                schedule.resume_run_id = None
            else:
                schedule.resume_run_id = None
                last = aware(schedule.last_started_at)
                if schedule.once and last is not None:
                    continue
                if last is not None and now < last + timedelta(minutes=schedule.interval_minutes):
                    continue
                run = new_run(
                    session,
                    config,
                    list(schedule.targets),
                    name=schedule.name
                    if schedule.once
                    else f"{schedule.name} {now:%Y-%m-%d %H:%M}",
                    settings=schedule.settings,
                    actor=f"system:schedule:{schedule.name}"[:255],
                    reason="Skan jednorazowy" if schedule.once else "Przebieg z harmonogramu",
                    schedule=schedule,
                    deadline=window.end,
                )
                schedule.last_started_at = now
        except RunError as error:
            audit.record(
                session,
                audit.AuditEvent(
                    actor="system:schedule",
                    action="discovery_schedule_failed",
                    reason=str(error)[:500],
                    inputs={},
                    object_type="discovery_schedule",
                    object_id=str(schedule.id),
                ),
            )
            session.commit()
            continue
        session.commit()
        dispatcher.run_discovery(run.id)
        started.append(run)
    return started
