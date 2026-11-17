"""Źródło online feedów. Jedyny moduł feedów z dostępem do sieci.

Łączy się wyłącznie ze stałą listą hostów (`FEED_HOSTS`), bez przekierowań. To nie jest
skanowanie, więc nie przechodzi przez allowlistę celów, ale ma własną, sztywną listę.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.feeds.base import FeedError, parse_datetime

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
FEED_HOSTS = frozenset({"services.nvd.nist.gov", "www.cisa.gov", "api.first.org"})

NVD_PAGE_SIZE = 2000
NVD_MAX_WINDOW = timedelta(days=119)
EPSS_BATCH = 100


class OnlineSource:
    mode = "online"

    def __init__(
        self,
        *,
        nvd_api_key: str = "",
        products: Sequence[tuple[str, str]] = (),
        recent_days: int = 2,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._api_key = nvd_api_key
        self._products = tuple(products)
        self._recent_days = recent_days
        self._client = client or httpx.Client(timeout=60, follow_redirects=False)
        self._sleep = sleep
        self._now = now
        # Limity NVD: 5 zapytań na 30 s bez klucza, 50 z kluczem.
        self._nvd_delay = 0.7 if nvd_api_key else 6.5

    def load(self, feed: str, *, cursor: str | None, cve_ids: Sequence[str] = ()) -> Any:
        if feed == "nvd":
            return {"vulnerabilities": self._nvd(cursor)}
        if feed == "kev":
            return self._get(KEV_URL)
        if feed == "epss":
            return {"data": self._epss(cve_ids)}
        raise FeedError(f"Nieznany feed: {feed}")

    def _get(
        self, url: str, params: dict[str, str] | None = None, headers: dict[str, str] | None = None
    ) -> Any:
        host = urlsplit(url).hostname or ""
        if host not in FEED_HOSTS or not url.startswith("https://"):
            raise FeedError(f"Host {host!r} nie jest na liście dozwolonych źródeł feedów")
        try:
            response = self._client.get(url, params=params, headers=headers)
        except httpx.HTTPError as error:
            raise FeedError(f"{host}: błąd połączenia ({error.__class__.__name__})") from error
        if response.status_code != 200:
            raise FeedError(f"{host}: odpowiedź HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as error:
            raise FeedError(f"{host}: odpowiedź nie jest JSON-em") from error

    def _nvd_pages(self, params: dict[str, str]) -> list[dict[str, Any]]:
        headers = {"apiKey": self._api_key} if self._api_key else None
        items: list[dict[str, Any]] = []
        start = 0
        while True:
            page = self._get(
                NVD_URL,
                {**params, "resultsPerPage": str(NVD_PAGE_SIZE), "startIndex": str(start)},
                headers,
            )
            batch = page.get("vulnerabilities") if isinstance(page, dict) else None
            if not isinstance(batch, list):
                raise FeedError("NVD: nieoczekiwany format strony wyników")
            items.extend(batch)
            total = int(page.get("totalResults", len(items)))
            start += len(batch)
            self._sleep(self._nvd_delay)
            if not batch or start >= total:
                return items

    def _nvd(self, cursor: str | None) -> list[dict[str, Any]]:
        now = self._now()
        seen: dict[str, dict[str, Any]] = {}

        def collect(items: list[dict[str, Any]]) -> None:
            for item in items:
                cve_id = (item.get("cve") or {}).get("id")
                if cve_id:
                    seen[str(cve_id)] = item

        since = parse_datetime(cursor)
        if since is None:
            # Pierwsze pobranie: CVE dla obserwowanych produktów oraz z ostatnich dni.
            for vendor, product in self._products:
                collect(self._nvd_pages({"virtualMatchString": f"cpe:2.3:*:{vendor}:{product}"}))
            since = now - timedelta(days=self._recent_days)
        while since < now:
            end = min(since + NVD_MAX_WINDOW, now)
            collect(
                self._nvd_pages(
                    {
                        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                    }
                )
            )
            since = end
        return list(seen.values())

    def _epss(self, cve_ids: Sequence[str]) -> list[dict[str, Any]]:
        data: list[dict[str, Any]] = []
        ids = sorted(set(cve_ids))
        for offset in range(0, len(ids), EPSS_BATCH):
            page = self._get(EPSS_URL, {"cve": ",".join(ids[offset : offset + EPSS_BATCH])})
            batch = page.get("data") if isinstance(page, dict) else None
            if not isinstance(batch, list):
                raise FeedError("EPSS: nieoczekiwany format odpowiedzi")
            data.extend(batch)
        return data
