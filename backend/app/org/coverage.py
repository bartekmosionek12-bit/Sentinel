"""Metryka pokrycia inwentarza (ARCHITECTURE §8.6, #18).

Trzy liczby mówią, ile wiemy o własnych urządzeniach: jaki odsetek ma właściciela (osobę albo
dział), jaki był skanowany w ostatnich 7 dniach i dla jakiego znamy wersję choć jednego
oprogramowania. Licznik nieznanych urządzeń to wynik reguły shadow IT. Jeden wiersz na dzień
daje szereg czasowy na wykres; ponowne liczenie w tym samym dniu nadpisuje wiersz.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.feeds.base import as_utc
from app.models import (
    Asset,
    AssetAssignment,
    AssetSource,
    CoverageSnapshot,
    Finding,
    Software,
)
from app.models.base import utcnow
from app.org.shadow import NON_DEVICE_TYPES

SCAN_WINDOW_DAYS = 7
OPEN = ("open", "acknowledged", "in_progress")


def _percent(part: int, total: int) -> float:
    return round(100.0 * part / total, 1) if total else 0.0


def measure(session: Session, *, now: datetime | None = None) -> dict[str, int]:
    now = now or utcnow()
    devices = session.scalars(
        select(Asset).where(
            Asset.type.not_in(NON_DEVICE_TYPES), Asset.status.in_(("active", "shadow", "missing"))
        )
    ).all()
    ids = {a.id for a in devices}
    owned = set(
        session.scalars(select(AssetAssignment.asset_id).where(AssetAssignment.role == "owner"))
    )
    with_owner = sum(1 for a in devices if a.id in owned or a.org_unit_id is not None)
    since = now - timedelta(days=SCAN_WINDOW_DAYS)
    scanned = {
        asset_id
        for asset_id, last_seen in session.execute(
            select(AssetSource.asset_id, AssetSource.last_seen).where(AssetSource.source == "scan")
        ).all()
        if as_utc(last_seen) >= since
    }
    versioned = set(
        session.scalars(
            select(Software.asset_id).where(Software.version.is_not(None), Software.version != "")
        )
    )
    open_findings = session.scalar(
        select(func.count()).select_from(Finding).where(Finding.status.in_(OPEN))
    )
    critical = session.scalar(
        select(func.count())
        .select_from(Finding)
        .where(Finding.status.in_(OPEN), Finding.risk_level == "krytyczny")
    )
    return {
        "assets_total": len(devices),
        "with_owner": with_owner,
        "scanned_recently": len(scanned & ids),
        "known_version": len(versioned & ids),
        "unknown_devices": sum(1 for a in devices if a.status == "shadow"),
        "open_findings": int(open_findings or 0),
        "critical_findings": int(critical or 0),
    }


def record_snapshot(
    session: Session, *, today: date | None = None, now: datetime | None = None
) -> CoverageSnapshot:
    now = now or utcnow()
    today = today or now.date()
    values = measure(session, now=now)
    row = session.scalar(select(CoverageSnapshot).where(CoverageSnapshot.day == today))
    if row is None:
        row = CoverageSnapshot(day=today, **values)
        session.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
    session.flush()
    return row


def as_view(row: CoverageSnapshot) -> dict[str, Any]:
    total = row.assets_total
    return {
        "day": row.day.isoformat(),
        "assets_total": total,
        "unknown_devices": row.unknown_devices,
        "open_findings": row.open_findings,
        "critical_findings": row.critical_findings,
        "with_owner_pct": _percent(row.with_owner, total),
        "scanned_recently_pct": _percent(row.scanned_recently, total),
        "known_version_pct": _percent(row.known_version, total),
    }
