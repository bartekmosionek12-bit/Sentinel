"""NVD API 2.0: CVE, CVSS i zakresy podatnych wersji (CPE)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.feeds.base import (
    AffectedRecord,
    ApplyResult,
    FeedError,
    FeedSource,
    VulnRecord,
    parse_datetime,
    same_instant,
)
from app.matching.cpe import parse_cpe
from app.models import CpeProduct, VulnAffected, Vulnerability

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, int | float):
            return float(score), data.get("vectorString")
    return None, None


def _affected(configurations: Sequence[dict[str, Any]]) -> tuple[AffectedRecord, ...]:
    records: dict[AffectedRecord, None] = {}
    for configuration in configurations:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parsed = parse_cpe(str(match.get("criteria", "")))
                if parsed is None:
                    continue
                vendor, product, version = parsed
                bounds = {
                    "start_including": match.get("versionStartIncluding"),
                    "start_excluding": match.get("versionStartExcluding"),
                    "end_including": match.get("versionEndIncluding"),
                    "end_excluding": match.get("versionEndExcluding"),
                }
                has_bounds = any(bounds.values())
                records[
                    AffectedRecord(
                        vendor=vendor,
                        product=product,
                        version_exact=None if has_bounds else version,
                        **bounds,
                    )
                ] = None
    return tuple(records)


class NvdFeed:
    name = "nvd"

    def fetch(self, source: FeedSource, *, cursor: str | None, cve_ids: Sequence[str] = ()) -> Any:
        return source.load(self.name, cursor=cursor, cve_ids=cve_ids)

    def normalize(self, raw: Any) -> list[VulnRecord]:
        if not isinstance(raw, dict) or not isinstance(raw.get("vulnerabilities"), list):
            raise FeedError("NVD: brak listy `vulnerabilities`")
        records: list[VulnRecord] = []
        for item in raw["vulnerabilities"]:
            cve = item.get("cve") if isinstance(item, dict) else None
            if not isinstance(cve, dict):
                continue
            cve_id = str(cve.get("id", ""))
            if not CVE_ID_RE.match(cve_id) or cve.get("vulnStatus") == "Rejected":
                continue
            descriptions = cve.get("descriptions") or []
            description = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
            )
            score, vector = _cvss(cve.get("metrics") or {})
            references = cve.get("references") or []
            records.append(
                VulnRecord(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=score,
                    cvss_vector=vector,
                    published=parse_datetime(cve.get("published")),
                    last_modified=parse_datetime(cve.get("lastModified")),
                    references=tuple(str(r["url"]) for r in references if r.get("url"))[:20],
                    has_public_exploit=any("Exploit" in (r.get("tags") or []) for r in references),
                    affected=_affected(cve.get("configurations") or []),
                )
            )
        return records

    def apply(self, session: Session, records: Sequence[VulnRecord]) -> ApplyResult:
        result = ApplyResult()
        known_products = {
            (v, p) for v, p in session.execute(select(CpeProduct.vendor, CpeProduct.product))
        }
        for record in records:
            vuln = session.scalar(
                select(Vulnerability).where(Vulnerability.cve_id == record.cve_id)
            )
            if vuln is None:
                vuln = Vulnerability(cve_id=record.cve_id, source="nvd")
                session.add(vuln)
                result.new += 1
                changed = True
            else:
                changed = (
                    vuln.source != "nvd"
                    or not same_instant(vuln.last_modified, record.last_modified)
                    or vuln.cvss_score != record.cvss_score
                )
                if changed:
                    result.updated += 1
            if changed:
                vuln.source = "nvd"
                vuln.description = record.description
                vuln.cvss_score = record.cvss_score
                vuln.cvss_vector = record.cvss_vector
                vuln.published = record.published
                vuln.last_modified = record.last_modified
                vuln.references = list(record.references)
                vuln.has_public_exploit = record.has_public_exploit
                vuln.affected = [
                    VulnAffected(
                        cpe_vendor=a.vendor,
                        cpe_product=a.product,
                        version_exact=a.version_exact,
                        start_including=a.start_including,
                        start_excluding=a.start_excluding,
                        end_including=a.end_including,
                        end_excluding=a.end_excluding,
                        fixed_version=a.fixed_version,
                    )
                    for a in record.affected
                ]
                result.changed_cves.add(record.cve_id)
            for affected in record.affected:
                key = (affected.vendor, affected.product)
                if key not in known_products:
                    known_products.add(key)
                    session.add(
                        CpeProduct(
                            vendor=affected.vendor,
                            product=affected.product,
                            title=f"{affected.vendor} {affected.product}".replace("_", " "),
                        )
                    )
            if record.last_modified is not None:
                stamp = record.last_modified.isoformat()
                if result.cursor is None or stamp > result.cursor:
                    result.cursor = stamp
        session.flush()
        return result
