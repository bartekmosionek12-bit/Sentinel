"""FIRST EPSS: prawdopodobieństwo wykorzystania podatności."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.feeds.base import ApplyResult, EpssRecord, FeedError, FeedSource
from app.feeds.nvd import CVE_ID_RE
from app.models import Vulnerability


class EpssFeed:
    name = "epss"

    def fetch(self, source: FeedSource, *, cursor: str | None, cve_ids: Sequence[str] = ()) -> Any:
        return source.load(self.name, cursor=cursor, cve_ids=cve_ids)

    def normalize(self, raw: Any) -> list[EpssRecord]:
        if not isinstance(raw, dict) or not isinstance(raw.get("data"), list):
            raise FeedError("EPSS: brak listy `data`")
        records = []
        for item in raw["data"]:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cve", ""))
            if not CVE_ID_RE.match(cve_id):
                continue
            try:
                epss = float(item["epss"])
                percentile = float(item["percentile"]) if item.get("percentile") else None
            except (KeyError, TypeError, ValueError):
                continue
            if not 0.0 <= epss <= 1.0:
                continue
            records.append(EpssRecord(cve_id=cve_id, epss=epss, percentile=percentile))
        return records

    def apply(self, session: Session, records: Sequence[EpssRecord]) -> ApplyResult:
        """Aktualizuje tylko podatności, które już znamy (nie importuje całego EPSS)."""
        result = ApplyResult()
        by_id = {r.cve_id: r for r in records}
        if not by_id:
            return result
        for vuln in session.scalars(
            select(Vulnerability).where(Vulnerability.cve_id.in_(list(by_id)))
        ):
            record = by_id[vuln.cve_id]
            if vuln.epss is None or round(vuln.epss, 3) != round(record.epss, 3):
                result.updated += 1
                result.changed_cves.add(vuln.cve_id)
            vuln.epss = record.epss
            vuln.epss_percentile = record.percentile
        session.flush()
        return result
