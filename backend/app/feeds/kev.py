"""CISA KEV: katalog podatności aktywnie wykorzystywanych."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.feeds.base import ApplyResult, FeedError, FeedSource, KevRecord, parse_date
from app.feeds.nvd import CVE_ID_RE
from app.models import Vulnerability


class KevFeed:
    name = "kev"

    def fetch(self, source: FeedSource, *, cursor: str | None, cve_ids: Sequence[str] = ()) -> Any:
        return source.load(self.name, cursor=cursor, cve_ids=cve_ids)

    def normalize(self, raw: Any) -> list[KevRecord]:
        if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
            raise FeedError("KEV: brak listy `vulnerabilities`")
        records = []
        for item in raw["vulnerabilities"]:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cveID", ""))
            if not CVE_ID_RE.match(cve_id):
                continue
            records.append(
                KevRecord(
                    cve_id=cve_id,
                    vendor_project=str(item.get("vendorProject", "")),
                    product=str(item.get("product", "")),
                    name=str(item.get("vulnerabilityName", "")),
                    description=str(item.get("shortDescription", "")),
                    required_action=str(item.get("requiredAction", "")),
                    date_added=parse_date(item.get("dateAdded")),
                    due_date=parse_date(item.get("dueDate")),
                )
            )
        return records

    def apply(self, session: Session, records: Sequence[KevRecord]) -> ApplyResult:
        result = ApplyResult()
        for record in records:
            vuln = session.scalar(
                select(Vulnerability).where(Vulnerability.cve_id == record.cve_id)
            )
            if vuln is None:
                # Sygnał wcześniejszy niż NVD: zapisujemy to, co wiemy z KEV.
                vuln = Vulnerability(
                    cve_id=record.cve_id,
                    source="kev",
                    description=record.description or record.name,
                    has_public_exploit=True,
                )
                session.add(vuln)
                result.new += 1
                changed = True
            else:
                changed = not vuln.in_kev or vuln.kev_due_date != record.due_date
                if changed:
                    result.updated += 1
            if changed:
                result.changed_cves.add(record.cve_id)
            vuln.in_kev = True
            vuln.kev_due_date = record.due_date
            vuln.kev_date_added = record.date_added
            vuln.kev_vendor_project = record.vendor_project or None
            vuln.kev_product = record.product or None
            vuln.kev_required_action = record.required_action or None
            if record.date_added is not None:
                stamp = record.date_added.isoformat()
                if result.cursor is None or stamp > result.cursor:
                    result.cursor = stamp
        session.flush()
        return result
