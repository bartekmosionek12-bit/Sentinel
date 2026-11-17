"""Wspólny interfejs feedów threat intelligence.

Każdy feed to adapter `ThreatFeed`: `fetch` pobiera surowe dane ze źródła (sieć albo
plik snapshotu), `normalize` sprowadza je do wspólnych rekordów, a `apply` zapisuje
do bazy i zwraca identyfikatory CVE, które się zmieniły. Tryb offline to ta sama
ścieżka kodu z innym źródłem bajtów.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy.orm import Session


class FeedError(Exception):
    """Źródło jest niedostępne albo zwróciło dane w nieoczekiwanym formacie."""


@dataclass(frozen=True)
class AffectedRecord:
    vendor: str
    product: str
    version_exact: str | None = None
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    @property
    def fixed_version(self) -> str | None:
        return self.end_excluding


@dataclass(frozen=True)
class VulnRecord:
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published: datetime | None = None
    last_modified: datetime | None = None
    references: tuple[str, ...] = ()
    has_public_exploit: bool = False
    affected: tuple[AffectedRecord, ...] = ()


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    vendor_project: str = ""
    product: str = ""
    name: str = ""
    description: str = ""
    required_action: str = ""
    date_added: date | None = None
    due_date: date | None = None


@dataclass(frozen=True)
class EpssRecord:
    cve_id: str
    epss: float
    percentile: float | None = None


@dataclass
class ApplyResult:
    new: int = 0
    updated: int = 0
    changed_cves: set[str] = field(default_factory=set)
    cursor: str | None = None


class FeedSource(Protocol):
    """Skąd pochodzą surowe dane feedu."""

    mode: str

    def load(self, feed: str, *, cursor: str | None, cve_ids: Sequence[str] = ()) -> Any: ...


class ThreatFeed(Protocol):
    name: str

    def fetch(self, source: FeedSource, *, cursor: str | None, cve_ids: Sequence[str]) -> Any: ...

    def normalize(self, raw: Any) -> Sequence[Any]: ...

    def apply(self, session: Session, records: Sequence[Any]) -> ApplyResult: ...


class OfflineSource:
    """Snapshoty z plików `<katalog>/<feed>.json` (demo bez internetu)."""

    mode = "offline"

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    def load(self, feed: str, *, cursor: str | None, cve_ids: Sequence[str] = ()) -> Any:
        path = self._directory / f"{feed}.json"
        if not path.is_file():
            raise FeedError(f"Brak snapshotu feedu {feed}: {path}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise FeedError(f"Snapshot {path} nie jest poprawnym JSON-em") from error


def parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return as_utc(parsed)


def as_utc(value: datetime) -> datetime:
    """SQLite nie przechowuje strefy, więc daty bez strefy traktujemy jako UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def same_instant(left: datetime | None, right: datetime | None) -> bool:
    if left is None or right is None:
        return left is right
    return as_utc(left) == as_utc(right)


def parse_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None
