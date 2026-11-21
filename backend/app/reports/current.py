"""„Aktualny obraz”, świeżość danych i prośby o skanowanie (moduł 21, ARCHITECTURE §25.1).

- „Aktualny obraz”: raport `assessment` z bieżącego stanu bazy, bez skanowania. Fakty i
  światło liczy kod; „W skrócie” na start z szablonu, model dopisuje je w tle.
- Świeżość: kiedy był ostatni zakończony skan i synchronizacja feedów; dane starsze niż próg
  z `rules/reports.yaml` (`freshness_hours`) dostają ostrzeżenie.
- Prośba o skanowanie: menedżer (`scan:request`) tylko składa prośbę. Admin (`scan:run`)
  zatwierdza ją i dopiero wtedy rusza zwykły skan (planner, `scope_guard`, poziomy, limity).
  Po skanie prosząca osoba dostaje powiadomienie w konsoli.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.feeds.base import as_utc
from app.models import Asset, FeedSync, Notification, OrgUnit, Report, ScanRequest, ScanRun
from app.models.base import utcnow
from app.reports.config import ReportsConfig
from app.reports.service import create_report

# Druga prośba o „Aktualny obraz” w tym oknie zwraca ten sam raport (klik dwa razy).
SNAPSHOT_DEBOUNCE = timedelta(minutes=1)
REQUEST_TRIGGER = "manager_request"


class ScanRequestError(ValueError):
    """Prośby nie da się złożyć albo rozpatrzyć (zły zakres, zły stan)."""


@dataclass(frozen=True)
class Freshness:
    last_scan_at: datetime | None
    last_feeds_at: datetime | None
    threshold_hours: int
    now: datetime

    @property
    def age_hours(self) -> float | None:
        if self.last_scan_at is None:
            return None
        return (self.now - as_utc(self.last_scan_at)).total_seconds() / 3600

    @property
    def stale(self) -> bool:
        age = self.age_hours
        return age is None or age > self.threshold_hours

    def label(self) -> str:
        """Zdanie dla menedżera, np. „Dane ze skanu sprzed 2 godzin”."""
        age = self.age_hours
        if age is None:
            return "Nie było jeszcze skanu: dane pochodzą tylko z inwentarza i katalogów."
        if age < 1:
            minutes = max(1, int(age * 60))
            return f"Dane ze skanu sprzed {minutes} min."
        if age < 48:
            return f"Dane ze skanu sprzed {int(age)} godz."
        return f"Dane ze skanu sprzed {int(age // 24)} dni."

    def as_dict(self) -> dict[str, Any]:
        return {
            "last_scan_at": self.last_scan_at.isoformat() if self.last_scan_at else None,
            "last_feeds_at": self.last_feeds_at.isoformat() if self.last_feeds_at else None,
            "age_hours": round(self.age_hours, 2) if self.age_hours is not None else None,
            "threshold_hours": self.threshold_hours,
            "stale": self.stale,
            "label": self.label(),
        }


def freshness(session: Session, config: ReportsConfig, now: datetime | None = None) -> Freshness:
    last_scan = session.scalar(
        select(ScanRun.finished_at)
        .where(ScanRun.status == "done", ScanRun.finished_at.is_not(None))
        .order_by(ScanRun.finished_at.desc())
        .limit(1)
    )
    last_feeds = session.scalar(
        select(FeedSync.finished_at)
        .where(FeedSync.finished_at.is_not(None))
        .order_by(FeedSync.finished_at.desc())
        .limit(1)
    )
    return Freshness(last_scan, last_feeds, config.freshness_hours, now or utcnow())


def current_picture(
    session: Session, config: ReportsConfig, *, actor: str, now: datetime | None = None
) -> tuple[Report, bool]:
    """Raport z bieżącego stanu. Zwraca (raport, czy nowy)."""
    now = now or utcnow()
    recent = session.scalar(
        select(Report)
        .where(Report.kind == "assessment", Report.created_by == actor)
        .order_by(Report.created_at.desc())
        .limit(1)
    )
    if (
        recent is not None
        and recent.scope.get("on_demand")
        and as_utc(recent.created_at) > now - SNAPSHOT_DEBOUNCE
    ):
        return recent, False
    fresh = freshness(session, config, now)
    report = create_report(
        session,
        config,
        kind="assessment",
        actor=actor,
        today=now.date(),
        extra_scope={"on_demand": True, "freshness": fresh.as_dict()},
    )
    return report, True


def _scope_label(session: Session, kind: str, ref: uuid.UUID | None) -> str:
    if kind == "organization":
        if ref is not None:
            raise ScanRequestError("Prośba o całą organizację nie wskazuje działu ani urządzenia")
        return "cała organizacja"
    if ref is None:
        raise ScanRequestError("Wskaż dział albo urządzenie")
    if kind == "unit":
        unit = session.get(OrgUnit, ref)
        if unit is None:
            raise ScanRequestError("Nie ma takiego działu")
        return f"dział: {unit.name}"
    asset = session.get(Asset, ref)
    if asset is None:
        raise ScanRequestError("Nie ma takiego urządzenia")
    return f"urządzenie: {asset.name}"


def request_scan(
    session: Session, *, actor: str, scope_kind: str, scope_ref: uuid.UUID | None, reason: str
) -> ScanRequest:
    label = _scope_label(session, scope_kind, scope_ref)
    pending = session.scalar(
        select(ScanRequest).where(
            ScanRequest.requested_by == actor,
            ScanRequest.status == "pending",
            ScanRequest.scope_kind == scope_kind,
            ScanRequest.scope_ref == scope_ref
            if scope_ref is not None
            else ScanRequest.scope_ref.is_(None),
        )
    )
    if pending is not None:
        return pending
    request = ScanRequest(
        requested_by=actor,
        scope_kind=scope_kind,
        scope_ref=scope_ref,
        scope_label=label,
        reason=reason.strip()[:1000],
    )
    session.add(request)
    session.flush()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="scan_requested",
            reason=f"Prośba o nowe skanowanie ({label}); czeka na zatwierdzenie admina",
            inputs={"scope_kind": scope_kind, "scope": label},
            object_type="scan_request",
            object_id=str(request.id),
        ),
    )
    return request


def decide_scan_request(
    session: Session, request_id: uuid.UUID, *, actor: str, approve: bool, reason: str
) -> ScanRequest:
    request = session.get(ScanRequest, request_id)
    if request is None:
        raise ScanRequestError("Nie ma takiej prośby")
    if request.status != "pending":
        raise ScanRequestError("Prośba została już rozpatrzona")
    request.status = "approved" if approve else "rejected"
    request.decided_by = actor
    request.decision_reason = reason.strip()[:1000] or None
    request.decided_at = utcnow()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="scan_request_approved" if approve else "scan_request_rejected",
            reason=(
                f"Prośba {request.requested_by} ({request.scope_label}) "
                + ("zatwierdzona: skan przechodzi zwykłą ścieżką" if approve else "odrzucona")
                + (f": {request.decision_reason}" if request.decision_reason else "")
            ),
            inputs={"requested_by": request.requested_by, "scope": request.scope_label},
            object_type="scan_request",
            object_id=str(request.id),
        ),
    )
    if not approve:
        _notify(session, request, f"Prośba o skanowanie ({request.scope_label}) odrzucona")
    session.flush()
    return request


def finish_scan_request(session: Session, request_id: uuid.UUID, run: ScanRun) -> None:
    """Wołane przez worker po skanie z prośby: łączy skan i powiadamia osobę, która prosiła."""
    request = session.get(ScanRequest, request_id)
    if request is None:
        return
    request.scan_run_id = run.id
    request.status = "done" if run.status == "done" else "failed"
    request.finished_at = utcnow()
    _notify(
        session,
        request,
        f"Wyniki skanowania gotowe ({request.scope_label})"
        if request.status == "done"
        else f"Skanowanie nie powiodło się ({request.scope_label})",
    )
    session.flush()


def _notify(session: Session, request: ScanRequest, title: str) -> None:
    session.add(
        Notification(
            rule_name="prosba_o_skan",
            channel="in_app",
            group_key=f"scan_request:{request.id}",
            status="sent",
            payload={
                "title": title,
                "lines": [request.decision_reason] if request.decision_reason else [],
                "scan_request_id": str(request.id),
                "recipient": request.requested_by,
            },
        )
    )
