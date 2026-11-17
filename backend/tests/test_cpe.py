"""Normalizacja produktu do CPE: aliasy, CPE z narzędzia, dopasowanie rozmyte."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.matching.cpe import (
    CpeEntry,
    MatchingConfig,
    ProductNormalizer,
    load_aliases,
    normalize_name,
    parse_cpe,
)

RULES = Path(__file__).resolve().parents[2] / "rules"

DICTIONARY = [
    CpeEntry("apache", "http_server", "Apache HTTP Server"),
    CpeEntry("apache", "tomcat", "Apache Tomcat"),
    CpeEntry("f5", "nginx", "nginx"),
    CpeEntry("redis", "redis", "Redis"),
    CpeEntry("owasp", "juice_shop", "OWASP Juice Shop"),
    CpeEntry("gitlab", "gitlab", "GitLab Community Edition"),
    CpeEntry("grafana", "grafana", "Grafana"),
]


@pytest.fixture(scope="module")
def normalizer() -> ProductNormalizer:
    return ProductNormalizer(load_aliases(RULES / "product_aliases.yaml"), DICTIONARY)


@pytest.mark.parametrize(
    ("product", "expected"),
    [
        ("Apache httpd", ("apache", "http_server")),
        ("apache  HTTPD", ("apache", "http_server")),
        ("nginx", ("f5", "nginx")),
        ("Redis key-value store", ("redis", "redis")),
        ("OpenSSH", ("openbsd", "openssh")),
        ("PostgreSQL DB", ("postgresql", "postgresql")),
    ],
)
def test_alias_gives_full_confidence(
    normalizer: ProductNormalizer, product: str, expected: tuple[str, str]
) -> None:
    best = normalizer.resolve(product).best
    assert best is not None
    assert best.entry.key == expected
    assert (best.score, best.method) == (1.0, "alias")


def test_alias_wins_over_outdated_tool_cpe(normalizer: ProductNormalizer) -> None:
    """nmap podaje `igor_sysoev:nginx`, NVD używa `f5:nginx`: wygrywa słownik aliasów."""
    best = normalizer.resolve("nginx", tool_cpes=["cpe:/a:igor_sysoev:nginx:1.18.0"]).best
    assert best is not None
    assert best.entry.key == ("f5", "nginx")


def test_tool_cpe_is_trusted_only_when_known(normalizer: ProductNormalizer) -> None:
    known = normalizer.resolve("Grafana dashboards", tool_cpes=["cpe:/a:grafana:grafana:9.0"]).best
    assert known is not None
    assert (known.entry.key, known.score, known.method) == (("grafana", "grafana"), 1.0, "tool_cpe")
    unknown = normalizer.resolve("Zupełnie Nieznany", tool_cpes=["cpe:/a:nobody:nothing:1.0"]).best
    assert unknown is None or unknown.method == "fuzzy"


def test_fuzzy_match_scores_between_zero_and_one(normalizer: ProductNormalizer) -> None:
    resolution = normalizer.resolve("OWASP Juice Shop web application")
    assert resolution.best is not None
    assert resolution.best.entry.key == ("owasp", "juice_shop")
    assert resolution.best.method == "fuzzy"
    assert 0.6 <= resolution.best.score <= 1.0
    assert len(resolution.candidates) <= 3
    scores = [c.score for c in resolution.candidates]
    assert scores == sorted(scores, reverse=True)


def test_similar_names_do_not_reach_auto_threshold(normalizer: ProductNormalizer) -> None:
    """„GitLab Runner” to inny produkt niż „GitLab”: nie może przejść automatycznie."""
    config = MatchingConfig.from_file(RULES / "matching.yaml")
    best = normalizer.resolve("Gitlab Runner Prometheus exporter").best
    assert best is None or best.score < config.auto


def test_unrelated_name_scores_low(normalizer: ProductNormalizer) -> None:
    config = MatchingConfig.from_file(RULES / "matching.yaml")
    best = normalizer.resolve("Hikvision IP camera rtspd").best
    assert best is None or best.score < config.review


def test_empty_product_gives_no_match(normalizer: ProductNormalizer) -> None:
    assert normalizer.resolve("").best is None
    assert normalizer.resolve("   ").best is None


@pytest.mark.parametrize(
    ("cpe", "expected"),
    [
        ("cpe:/a:apache:http_server:2.4.49", ("apache", "http_server", "2.4.49")),
        ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", ("apache", "http_server", "2.4.49")),
        ("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", ("f5", "nginx", None)),
        ("cpe:/a:redislabs:redis", ("redislabs", "redis", None)),
        ("cpe:/o:linux:linux_kernel", ("linux", "linux_kernel", None)),
    ],
)
def test_parse_cpe(cpe: str, expected: tuple[str, str, str | None]) -> None:
    assert parse_cpe(cpe) == expected


@pytest.mark.parametrize("cpe", ["", "apache:http_server", "cpe:/a:apache", "cpe:2.3:a::x"])
def test_parse_cpe_rejects_garbage(cpe: str) -> None:
    assert parse_cpe(cpe) is None


def test_normalize_name() -> None:
    assert normalize_name("  Apache/httpd  (Unix) ") == "apache httpd unix"
    assert normalize_name("Node.js") == "node.js"


def test_conflicting_aliases_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "aliases.yaml"
    path.write_text(
        "aliases:\n"
        "  - {names: [httpd], vendor: apache, product: http_server}\n"
        "  - {names: [HTTPD], vendor: acme, product: other}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="dwa różne produkty"):
        load_aliases(path)


def test_invalid_thresholds_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "matching.yaml"
    path.write_text("thresholds: {auto: 0.5, review: 0.8}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="progi"):
        MatchingConfig.from_file(path)


@pytest.mark.parametrize("product", ["Shop", "Server", "HTTP", "Community Edition"])
def test_partial_word_overlap_never_matches_automatically(
    normalizer: ProductNormalizer, product: str
) -> None:
    """Jedno wspólne słowo to za mało: bez tego „Shop” stałby się OWASP Juice Shop."""
    config = MatchingConfig.from_file(RULES / "matching.yaml")
    best = normalizer.resolve(product).best
    assert best is None or best.score < config.auto
