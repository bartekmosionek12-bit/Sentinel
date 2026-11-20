"""Porównanie miniaturowego zestawu feedów z prawdziwym snapshotem.

Zestaw w `tests/fixtures/feeds/` jest przepisany ręcznie, więc może się rozjechać
z rzeczywistością. Gdy w `data/feeds/` (albo w katalogu z `FEEDS_SNAPSHOT_DIR`) leży
prawdziwy snapshot pobrany przez `scripts/fetch_feeds.sh`, te testy sprawdzają zgodność.
Bez snapshotu są pomijane, bo prawdziwe feedy nie trafiają do repozytorium.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from app.feeds.epss import EpssFeed
from app.feeds.kev import KevFeed
from app.feeds.nvd import NvdFeed

FIXTURES = Path(__file__).parent / "fixtures" / "feeds"
SNAPSHOT = Path(
    os.environ.get("FEEDS_SNAPSHOT_DIR") or Path(__file__).resolve().parents[2] / "data" / "feeds"
)
# Fikcyjne EPSS ma tylko nie wprowadzać w błąd co do rzędu wielkości.
EPSS_TOLERANCE = 0.25


def _load(directory: Path, name: str) -> Any:
    path = directory / f"{name}.json"
    if not path.is_file():
        pytest.skip(f"brak prawdziwego snapshotu {path} (pobiera go scripts/fetch_feeds.sh)")
    return json.loads(path.read_text(encoding="utf-8"))


def test_epss_fixture_is_marked_as_synthetic() -> None:
    raw = json.loads((FIXTURES / "epss.json").read_text(encoding="utf-8"))
    assert raw["synthetic"] is True
    assert "FIKCYJNE" in raw["note"]


def test_nvd_fixture_matches_real_snapshot() -> None:
    real = {r.cve_id: r for r in NvdFeed().normalize(_load(SNAPSHOT, "nvd"))}
    for record in NvdFeed().normalize(_load(FIXTURES, "nvd")):
        assert record.cve_id in real, f"{record.cve_id}: brak w prawdziwym snapshocie NVD"
        actual = real[record.cve_id]
        assert record.cvss_score == actual.cvss_score, f"{record.cve_id}: inna ocena CVSS"
        products = {(a.vendor, a.product) for a in record.affected}
        assert products <= {(a.vendor, a.product) for a in actual.affected}, (
            f"{record.cve_id}: produkt z zestawu demo nie występuje w NVD"
        )


def test_kev_fixture_matches_real_snapshot() -> None:
    real = {r.cve_id for r in KevFeed().normalize(_load(SNAPSHOT, "kev"))}
    in_fixture = {r.cve_id for r in KevFeed().normalize(_load(FIXTURES, "kev"))}
    all_demo = {r.cve_id for r in NvdFeed().normalize(_load(FIXTURES, "nvd"))}
    assert in_fixture <= real, (
        f"w zestawie demo jako KEV, a nie ma ich w katalogu: {in_fixture - real}"
    )
    missing = (all_demo & real) - in_fixture
    assert not missing, f"są w katalogu KEV, a w zestawie demo nie: {missing}"


def test_epss_fixture_is_close_to_real_snapshot() -> None:
    real = {r.cve_id: r.epss for r in EpssFeed().normalize(_load(SNAPSHOT, "epss"))}
    for record in EpssFeed().normalize(_load(FIXTURES, "epss")):
        if record.cve_id not in real:
            continue  # snapshot EPSS obejmuje tylko CVE znane systemowi w chwili pobrania
        assert abs(record.epss - real[record.cve_id]) <= EPSS_TOLERANCE, (
            f"{record.cve_id}: przykładowe EPSS {record.epss} odbiega od rzeczywistego "
            f"{real[record.cve_id]}; popraw wartość w tests/fixtures/feeds/epss.json"
        )
