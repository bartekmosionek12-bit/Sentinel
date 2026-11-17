"""Porównywanie wersji: semver, schematy niestandardowe i granice zakresów NVD."""

from __future__ import annotations

import pytest

from app.matching.versions import VersionRange, in_range, is_distro_version, parse_version


def v(text: str):  # type: ignore[no-untyped-def]
    parsed = parse_version(text)
    assert parsed is not None, text
    return parsed


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("2.4.48", "2.4.49"),
        ("2.4.9", "2.4.10"),
        ("2.4", "2.4.1"),
        ("1.18.0", "1.20.1"),
        ("1.9.9", "1.10.0"),
        ("0.6.18", "1.0.0"),
        ("8.2", "8.2p1"),
        ("8.2p1", "8.2p2"),
        ("8.2p1", "8.3"),
        ("1.0.2j", "1.0.2k"),
        ("1.0.2k", "1.0.2zh"),
        ("1.0.2", "1.0.2a"),
        ("1.2.3-beta2", "1.2.3"),
        ("1.2.3-alpha", "1.2.3-beta"),
        ("1.2.3-beta1", "1.2.3-beta2"),
        ("1.2.3-rc1", "1.2.3"),
        ("1.2.3-rc2", "1.2.4-alpha"),
        ("2021.04", "2021.10"),
        ("2021.10", "2022.01"),
        ("5.0.7", "6.2.7"),
        ("9.6.24", "10.0"),
        ("7.4.3", "7.4.33"),
    ],
)
def test_ordering(lower: str, higher: str) -> None:
    assert v(lower) < v(higher)
    assert v(higher) > v(lower)
    assert v(lower) != v(higher)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("2.4.49", "2.4.49"),
        ("1.2", "1.2.0"),
        ("1.2.0.0", "1.2"),
        ("v1.2.3", "1.2.3"),
        ("V2.0", "2.0"),
        ("1:1.3.1", "1.3.1"),
        ("1.0.2K", "1.0.2k"),
        (" 2.4.49 ", "2.4.49"),
    ],
)
def test_equality(left: str, right: str) -> None:
    assert v(left) == v(right)
    assert hash(v(left)) == hash(v(right))


@pytest.mark.parametrize(
    "text", [None, "", " ", "*", "-", "unknown", "latest", "n/a", "9.6.0 or later", "x.y", "<2.0"]
)
def test_unparseable_versions_return_none(text: str | None) -> None:
    assert parse_version(text) is None


@pytest.mark.parametrize(
    ("version", "bounds", "expected"),
    [
        # dokładna wersja (CVE-2021-41773 dotyczy tylko 2.4.49)
        ("2.4.49", VersionRange(exact="2.4.49"), True),
        ("2.4.50", VersionRange(exact="2.4.49"), False),
        ("2.4.48", VersionRange(exact="2.4.49"), False),
        # początek i koniec włącznie (2.4.49–2.4.50)
        ("2.4.49", VersionRange(start_including="2.4.49", end_including="2.4.50"), True),
        ("2.4.50", VersionRange(start_including="2.4.49", end_including="2.4.50"), True),
        ("2.4.51", VersionRange(start_including="2.4.49", end_including="2.4.50"), False),
        ("2.4.48", VersionRange(start_including="2.4.49", end_including="2.4.50"), False),
        # koniec wyłącznie (naprawione w 1.20.1)
        ("1.18.0", VersionRange(start_including="0.6.18", end_excluding="1.20.1"), True),
        ("1.20.0", VersionRange(start_including="0.6.18", end_excluding="1.20.1"), True),
        ("1.20.1", VersionRange(start_including="0.6.18", end_excluding="1.20.1"), False),
        ("0.6.17", VersionRange(start_including="0.6.18", end_excluding="1.20.1"), False),
        ("0.6.18", VersionRange(start_including="0.6.18", end_excluding="1.20.1"), True),
        # początek wyłącznie
        ("2.0", VersionRange(start_excluding="2.0", end_including="2.5"), False),
        ("2.0.1", VersionRange(start_excluding="2.0", end_including="2.5"), True),
        ("2.5", VersionRange(start_excluding="2.0", end_including="2.5"), True),
        # tylko górna granica
        ("2.4.25", VersionRange(end_including="2.4.48"), True),
        ("2.4.49", VersionRange(end_including="2.4.48"), False),
        ("5.0.7", VersionRange(end_excluding="6.2.7"), True),
        # tylko dolna granica
        ("3.0", VersionRange(start_including="2.0"), True),
        ("1.9", VersionRange(start_including="2.0"), False),
        # schematy niestandardowe
        ("8.2p1", VersionRange(end_excluding="8.3"), True),
        ("1.0.2k", VersionRange(start_including="1.0.2", end_excluding="1.0.2l"), True),
        ("1.0.2l", VersionRange(start_including="1.0.2", end_excluding="1.0.2l"), False),
        ("1.2.3-rc1", VersionRange(end_excluding="1.2.3"), True),
        # brak granic: wszystkie wersje
        ("1.0", VersionRange(), True),
        (None, VersionRange(), True),
    ],
)
def test_in_range(version: str | None, bounds: VersionRange, expected: bool) -> None:
    assert in_range(version, bounds) is expected


@pytest.mark.parametrize(
    ("version", "bounds"),
    [
        (None, VersionRange(exact="2.4.49")),
        ("", VersionRange(end_excluding="2.0")),
        ("9.6.0 or later", VersionRange(end_excluding="9.6.24")),
        ("unknown", VersionRange(start_including="1.0")),
        ("2.4.49", VersionRange(end_excluding="nie-wersja")),
        ("2.4.49", VersionRange(exact="*")),
    ],
)
def test_in_range_does_not_guess(version: str | None, bounds: VersionRange) -> None:
    assert in_range(version, bounds) is None


@pytest.mark.parametrize(
    "texts",
    [
        ("1.18.0-0ubuntu1.4",),
        ("2.4.25", "Apache httpd 2.4.25 ((Debian))"),
        ("7.4p1", "OpenSSH 7.4p1 Debian 10+deb9u7"),
        ("2.4.6-97.el7",),
        ("1.2.3-r4",),
        ("10.5.8", "MariaDB 10.5.8 (Ubuntu)"),
    ],
)
def test_distro_packages_are_detected(texts: tuple[str, ...]) -> None:
    assert is_distro_version(*texts)


@pytest.mark.parametrize(
    "texts", [("2.4.49", "Apache httpd 2.4.49 (Unix)"), ("1.18.0", "nginx 1.18.0"), ("5.0.7", None)]
)
def test_upstream_versions_are_not_distro(texts: tuple[str | None, ...]) -> None:
    assert not is_distro_version(*texts)


def test_range_description() -> None:
    assert VersionRange(exact="2.4.49").describe() == "= 2.4.49"
    described = VersionRange(start_including="0.6.18", end_excluding="1.20.1").describe()
    assert described == ">= 0.6.18, < 1.20.1"
    assert VersionRange().describe() == "wszystkie wersje"
