"""Synchronizacja feedów: jedna ścieżka dla trybu online i offline.

Każde uruchomienie zostawia wiersz `FeedSync` i wpis w audit logu, także przy błędzie.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.feeds.base import FeedError, FeedSource, ThreatFeed
from app.feeds.epss import EpssFeed
from app.feeds.kev import KevFeed
from app.feeds.nvd import NvdFeed
from app.models import FeedSync, Vulnerability
from app.models.base import utcnow

# Kolejność ma znaczenie: KEV i EPSS uzupełniają podatności znane z NVD.
FEEDS: dict[str, ThreatFeed] = {"nvd": NvdFeed(), "kev": KevFeed(), "epss": EpssFeed()}


@dataclass
class SyncSummary:
    changed_cves: set[str] = field(default_factory=set)
    results: dict[str, dict[str, object]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return all(r["status"] == "ok" for r in self.results.values())


def last_cursor(session: Session, feed: str, mode: str) -> str | None:
    return session.scalar(
        select(FeedSync.cursor)
        .where(FeedSync.feed == feed, FeedSync.mode == mode, FeedSync.status == "ok")
        .order_by(FeedSync.started_at.desc())
        .limit(1)
    )


def sync_feed(
    session: Session, name: str, source: FeedSource, *, actor: str = "system"
) -> tuple[FeedSync, set[str]]:
    feed = FEEDS[name]
    sync = FeedSync(feed=name, mode=source.mode, status="running")
    session.add(sync)
    session.flush()
    # Snapshot offline wczytujemy zawsze w całości; kursor ma sens tylko online.
    cursor = last_cursor(session, name, source.mode) if source.mode == "online" else None
    changed: set[str] = set()
    try:
        cve_ids = list(session.scalars(select(Vulnerability.cve_id))) if name == "epss" else []
        raw = feed.fetch(source, cursor=cursor, cve_ids=cve_ids)
        records = feed.normalize(raw)
        with session.begin_nested():
            result = feed.apply(session, records)
    except FeedError as error:
        sync.status = "failed"
        sync.error = str(error)
        sync.cursor = cursor
    else:
        sync.status = "ok"
        sync.items_new = result.new
        sync.items_updated = result.updated
        sync.cursor = result.cursor or cursor
        changed = result.changed_cves
    sync.finished_at = utcnow()
    audit.record(
        session,
        audit.AuditEvent(
            actor=actor,
            action="feed_synced" if sync.status == "ok" else "feed_failed",
            reason=(
                f"Synchronizacja feedu {name} w trybie {source.mode}"
                if sync.status == "ok"
                else f"Feed {name} niedostępny: {sync.error}"
            ),
            inputs={
                "feed": name,
                "mode": source.mode,
                "new": sync.items_new,
                "updated": sync.items_updated,
                "cursor": sync.cursor,
                "changed_cves": sorted(changed)[:50],
            },
            object_type="feed",
            object_id=name,
        ),
    )
    return sync, changed


def sync_all(session: Session, source: FeedSource, *, actor: str = "system") -> SyncSummary:
    """Synchronizuje wszystkie feedy. Błąd jednego nie zatrzymuje pozostałych."""
    summary = SyncSummary()
    for name in FEEDS:
        sync, changed = sync_feed(session, name, source, actor=actor)
        summary.changed_cves |= changed
        summary.results[name] = {
            "status": sync.status,
            "new": sync.items_new,
            "updated": sync.items_updated,
            "error": sync.error,
        }
    return summary
