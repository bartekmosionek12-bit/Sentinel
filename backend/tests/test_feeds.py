"""Feedy: normalizacja, zapis, tryb offline i źródło online bez prawdziwej sieci."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.feeds.base import FeedError, OfflineSource
from app.feeds.epss import EpssFeed
from app.feeds.http import EPSS_URL, KEV_URL, NVD_URL, OnlineSource
from app.feeds.kev import KevFeed
from app.feeds.nvd import NvdFeed
from app.feeds.service import sync_all, sync_feed
from app.models import AuditLog, CpeProduct, FeedSync, VulnAffected, Vulnerability

FEEDS_DIR = Path(__file__).parent / "fixtures" / "feeds"


@pytest.fixture
def offline() -> OfflineSource:
    return OfflineSource(FEEDS_DIR)


def _vuln(session: Session, cve_id: str) -> Vulnerability:
    vuln = session.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve_id))
    assert vuln is not None
    return vuln


def test_nvd_normalize_reads_cvss_ranges_and_exploit_flag(offline: OfflineSource) -> None:
    feed = NvdFeed()
    records = {r.cve_id: r for r in feed.normalize(feed.fetch(offline, cursor=None))}
    traversal = records["CVE-2021-41773"]
    assert traversal.cvss_score == 7.5
    assert traversal.has_public_exploit
    assert [(a.vendor, a.product, a.version_exact) for a in traversal.affected] == [
        ("apache", "http_server", "2.4.49")
    ]
    nginx = records["CVE-2021-23017"].affected[0]
    assert (nginx.start_including, nginx.end_excluding, nginx.version_exact) == (
        "0.6.18",
        "1.20.1",
        None,
    )
    assert nginx.fixed_version == "1.20.1"
    assert not records["CVE-2017-9798"].has_public_exploit


def test_nvd_normalize_skips_rejected_and_malformed_entries() -> None:
    raw = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2020-0001", "vulnStatus": "Rejected"}},
            {"cve": {"id": "not-a-cve"}},
            "garbage",
            {"cve": {"id": "CVE-2020-0002"}},
        ]
    }
    assert [r.cve_id for r in NvdFeed().normalize(raw)] == ["CVE-2020-0002"]


@pytest.mark.parametrize("feed", [NvdFeed(), KevFeed(), EpssFeed()])
def test_unexpected_format_is_a_feed_error(feed: NvdFeed | KevFeed | EpssFeed) -> None:
    with pytest.raises(FeedError):
        feed.normalize({"unexpected": True})


def test_offline_sync_fills_vulnerabilities_kev_and_epss(
    session: Session, offline: OfflineSource
) -> None:
    summary = sync_all(session, offline)
    assert summary.ok
    assert summary.results["nvd"]["new"] == 9
    assert "CVE-2021-41773" in summary.changed_cves

    vuln = _vuln(session, "CVE-2021-41773")
    assert vuln.in_kev
    assert vuln.kev_due_date == date(2021, 11, 17)
    assert vuln.epss == pytest.approx(0.97)
    assert vuln.cvss_score == 7.5
    assert not _vuln(session, "CVE-2021-23017").in_kev
    assert session.scalar(select(func.count()).select_from(CpeProduct)) == 5
    assert session.scalar(select(func.count()).select_from(VulnAffected)) == 10

    syncs = session.scalars(select(FeedSync)).all()
    assert {(s.feed, s.mode, s.status) for s in syncs} == {
        ("nvd", "offline", "ok"),
        ("kev", "offline", "ok"),
        ("epss", "offline", "ok"),
    }
    actions = session.scalars(select(AuditLog.action)).all()
    assert actions.count("feed_synced") == 3


def test_second_sync_of_the_same_snapshot_changes_nothing(
    session: Session, offline: OfflineSource
) -> None:
    sync_all(session, offline)
    again = sync_all(session, offline)
    assert again.changed_cves == set()
    assert all(r["new"] == 0 and r["updated"] == 0 for r in again.results.values())
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 9


def test_missing_snapshot_is_recorded_and_does_not_stop_other_feeds(
    session: Session, tmp_path: Path
) -> None:
    (tmp_path / "kev.json").write_text((FEEDS_DIR / "kev.json").read_text(), encoding="utf-8")
    summary = sync_all(session, OfflineSource(tmp_path))
    assert not summary.ok
    assert summary.results["nvd"]["status"] == "failed"
    assert summary.results["kev"]["status"] == "ok"
    assert "feed_failed" in session.scalars(select(AuditLog.action)).all()


def test_kev_before_nvd_creates_stub_that_nvd_later_completes(
    session: Session, offline: OfflineSource
) -> None:
    sync_feed(session, "kev", offline)
    stub = _vuln(session, "CVE-2021-44228")
    assert stub.source == "kev"
    assert stub.cvss_score is None
    assert stub.in_kev
    _, changed = sync_feed(session, "nvd", offline)
    assert "CVE-2021-44228" in changed
    session.refresh(stub)
    assert stub.source == "nvd"
    assert stub.cvss_score == 10.0
    assert stub.in_kev


def test_epss_ignores_unknown_cves_and_out_of_range_values(session: Session) -> None:
    session.add(Vulnerability(cve_id="CVE-2020-1111"))
    session.flush()
    feed = EpssFeed()
    records = feed.normalize(
        {
            "data": [
                {"cve": "CVE-2020-1111", "epss": "0.5", "percentile": "0.9"},
                {"cve": "CVE-2020-2222", "epss": "0.1"},
                {"cve": "CVE-2020-3333", "epss": "7"},
                {"cve": "CVE-2020-4444", "epss": "abc"},
            ]
        }
    )
    assert [r.cve_id for r in records] == ["CVE-2020-1111", "CVE-2020-2222"]
    result = feed.apply(session, records)
    assert result.changed_cves == {"CVE-2020-1111"}
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1


def _online(handler: httpx.MockTransport, **kwargs: object) -> OnlineSource:
    return OnlineSource(
        client=httpx.Client(transport=handler),
        sleep=lambda _seconds: None,
        now=lambda: datetime(2026, 11, 16, 12, 0, tzinfo=UTC),
        **kwargs,  # type: ignore[arg-type]
    )


def test_online_source_only_talks_to_fixed_feed_hosts() -> None:
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        if str(request.url).startswith(NVD_URL):
            start = int(request.url.params["startIndex"])
            items = [{"cve": {"id": f"CVE-2026-{1000 + start}"}}] if start < 2 else []
            return httpx.Response(200, json={"totalResults": 2, "vulnerabilities": items})
        if str(request.url).startswith(EPSS_URL):
            ids = request.url.params["cve"].split(",")
            return httpx.Response(200, json={"data": [{"cve": i, "epss": "0.1"} for i in ids]})
        return httpx.Response(200, json={"vulnerabilities": []})

    source = _online(httpx.MockTransport(handler), products=[("apache", "http_server")])
    nvd = source.load("nvd", cursor=None)
    assert {i["cve"]["id"] for i in nvd["vulnerabilities"]} == {"CVE-2026-1000", "CVE-2026-1001"}
    assert any("virtualMatchString" in u.params for u in seen)
    assert any("lastModStartDate" in u.params for u in seen)

    epss = source.load("epss", cursor=None, cve_ids=[f"CVE-2026-{n}" for n in range(1, 151)])
    assert len(epss["data"]) == 150
    assert source.load("kev", cursor=None) == {"vulnerabilities": []}
    assert {u.host for u in seen} == {"services.nvd.nist.gov", "api.first.org", "www.cisa.gov"}
    assert str(seen[-1]) == KEV_URL


def test_online_source_refuses_other_hosts_and_reports_http_errors() -> None:
    source = _online(httpx.MockTransport(lambda _request: httpx.Response(503)))
    with pytest.raises(FeedError, match="nie jest na liście"):
        source._get("https://example.com/feed.json")
    with pytest.raises(FeedError, match="nie jest na liście"):
        source._get("http://www.cisa.gov/feed.json")
    with pytest.raises(FeedError, match="HTTP 503"):
        source.load("kev", cursor=None)
    with pytest.raises(FeedError, match="Nieznany feed"):
        source.load("other", cursor=None)


def test_online_sync_resumes_from_cursor(session: Session) -> None:
    starts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        starts.append(request.url.params.get("lastModStartDate", ""))
        return httpx.Response(
            200,
            json={
                "totalResults": 1,
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2026-0001", "lastModified": "2026-11-16T10:00:00.000"}}
                ],
            },
        )

    source = _online(httpx.MockTransport(handler))
    first, _ = sync_feed(session, "nvd", source)
    assert first.cursor is not None
    assert first.cursor.startswith("2026-11-16T10:00:00")
    sync_feed(session, "nvd", source)
    assert starts[-1].startswith("2026-11-16T10:00:00")
