"""Risk scoring: jawna formuła, rozbicie wyniku, walidacja konfiguracji."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.scoring.engine import Premium, RiskInputs, ScoringConfig, score_risk

RULES = Path(__file__).resolve().parents[2] / "rules"


@pytest.fixture(scope="module")
def config() -> ScoringConfig:
    return ScoringConfig.from_file(RULES / "scoring.yaml")


def raw_config() -> dict[str, Any]:
    return {
        "version": "t",
        "weights": {
            "cvss": 0.30,
            "epss": 0.20,
            "kev": 0.20,
            "exposure": 0.15,
            "criticality": 0.10,
            "exploit": 0.05,
        },
        "exposure_values": {"internet": 100, "internal": 30},
        "levels": {"krytyczny": 80, "wysoki": 60, "średni": 40, "niski": 0},
        "severity_values": {"critical": 95, "high": 80, "medium": 55, "low": 25},
    }


def test_documented_example_internet_facing(config: ScoringConfig) -> None:
    """Przykład z ARCHITECTURE.md: Apache 2.4.49, CVE-2021-41773, internet, krytyczność 4."""
    result = score_risk(
        RiskInputs(
            exposure="internet",
            criticality=4,
            cvss=7.5,
            epss=0.94,
            in_kev=True,
            has_public_exploit=True,
        ),
        config,
    )
    assert result.score == 88.8
    assert result.level == "krytyczny"
    contributions = {c["name"]: c["contribution"] for c in result.breakdown["components"]}
    assert contributions == {
        "cvss": 22.5,
        "epss": 18.8,
        "kev": 20.0,
        "exposure": 15.0,
        "criticality": 7.5,
        "exploit": 5.0,
    }
    assert result.breakdown["summary"] == (
        "Krytyczny, bo: Wysoka ocena CVSS + Aktywnie wykorzystywana (KEV) "
        "+ Wysokie prawdopodobieństwo wykorzystania (EPSS)"
    )
    assert result.breakdown["config_version"] == config.version


def test_same_cve_scores_lower_on_internal_low_criticality_asset(config: ScoringConfig) -> None:
    result = score_risk(
        RiskInputs(
            exposure="internal",
            criticality=2,
            cvss=7.5,
            epss=0.94,
            in_kev=True,
            has_public_exploit=True,
        ),
        config,
    )
    assert result.score == 73.3
    assert result.level == "wysoki"


def test_context_changes_priority_not_cvss(config: ScoringConfig) -> None:
    """CVSS 9.8 bez KEV w sieci wewnętrznej jest niżej niż CVSS 7.5 z KEV w internecie."""
    loud = score_risk(RiskInputs("internal", 2, cvss=9.8, epss=0.02), config)
    real = score_risk(RiskInputs("internet", 4, cvss=7.5, epss=0.94, in_kev=True), config)
    assert loud.score < real.score
    assert loud.level == "niski"


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (100, "krytyczny"),
        (80, "krytyczny"),
        (79.9, "wysoki"),
        (60, "wysoki"),
        (59.9, "średni"),
        (40, "średni"),
        (39.9, "niski"),
        (0, "niski"),
    ],
)
def test_level_thresholds(config: ScoringConfig, score: float, level: str) -> None:
    assert config.level_for(score) == level


def test_score_is_deterministic_and_bounded(config: ScoringConfig) -> None:
    inputs = RiskInputs("internet", 5, cvss=10.0, epss=1.0, in_kev=True, has_public_exploit=True)
    first = score_risk(inputs, config)
    assert first == score_risk(inputs, config)
    assert first.score == 100.0
    lowest = score_risk(RiskInputs("internal", 1), config)
    assert lowest.score == 4.5  # tylko ekspozycja wewnętrzna: 30 × 0.15
    assert lowest.level == "niski"


def test_missing_cvss_and_epss_count_as_zero_and_say_so(config: ScoringConfig) -> None:
    result = score_risk(RiskInputs("internet", 3, in_kev=True), config)
    by_name = {c["name"]: c for c in result.breakdown["components"]}
    assert by_name["cvss"]["contribution"] == 0
    assert by_name["cvss"]["source"] == "brak oceny CVSS"
    assert by_name["epss"]["source"] == "brak danych EPSS"
    assert result.score == 40.0  # KEV 20 + internet 15 + krytyczność 5


def test_rule_severity_replaces_cvss_for_non_cve_findings(config: ScoringConfig) -> None:
    result = score_risk(RiskInputs("internet", 4, severity="high"), config)
    by_name = {c["name"]: c for c in result.breakdown["components"]}
    assert by_name["cvss"]["value"] == 80
    assert by_name["cvss"]["source"] == "waga reguły: high"
    assert result.score == 46.5


def test_attack_chain_premium_is_added_and_capped(config: ScoringConfig) -> None:
    inputs = RiskInputs("internet", 4, cvss=7.5, epss=0.94, in_kev=True, has_public_exploit=True)
    premium = Premium("admin_panel_outdated_internet", 10, "Panel administracyjny w internecie")
    result = score_risk(inputs, config, (premium,))
    assert result.score == 98.8
    assert result.breakdown["base_score"] == 88.8
    assert result.breakdown["premiums"][0]["rule"] == "admin_panel_outdated_internet"
    assert result.breakdown["summary"].endswith("+ Panel administracyjny w internecie")
    capped = score_risk(inputs, config, (premium, Premium("x", 50)))
    assert capped.score == 100.0


def test_summary_lists_only_factors_that_raise_risk(config: ScoringConfig) -> None:
    result = score_risk(RiskInputs("internal", 1, cvss=3.1, epss=0.001), config)
    assert result.breakdown["summary"] == "Niski"


@pytest.mark.parametrize("criticality", [0, 6, -1])
def test_invalid_criticality_is_rejected(config: ScoringConfig, criticality: int) -> None:
    with pytest.raises(ValueError, match="1–5"):
        score_risk(RiskInputs("internet", criticality, cvss=5.0), config)


def test_unknown_exposure_is_rejected(config: ScoringConfig) -> None:
    with pytest.raises(ValueError, match="ekspozycja"):
        score_risk(RiskInputs("dmz", 3, cvss=5.0), config)


def test_weights_must_sum_to_one() -> None:
    data = raw_config()
    data["weights"]["cvss"] = 0.5
    with pytest.raises(ValueError, match="sumować się do 1"):
        ScoringConfig.from_dict(data)


def test_weights_must_cover_all_components() -> None:
    data = raw_config()
    del data["weights"]["exploit"]
    with pytest.raises(ValueError, match="dokładnie"):
        ScoringConfig.from_dict(data)


def test_levels_must_be_descending() -> None:
    data = raw_config()
    data["levels"]["wysoki"] = 90
    with pytest.raises(ValueError, match="maleć"):
        ScoringConfig.from_dict(data)


def test_changing_weights_changes_score_and_is_recorded() -> None:
    data = raw_config()
    data["version"] = "kev-heavy"
    data["weights"].update({"kev": 0.40, "cvss": 0.10})
    config = ScoringConfig.from_dict(data)
    result = score_risk(RiskInputs("internet", 4, cvss=7.5, epss=0.94, in_kev=True), config)
    assert result.score == 88.8
    assert result.breakdown["config_version"] == "kev-heavy"
