"""Ocena ryzyka findingu. Czysta funkcja: te same dane zawsze dają ten sam wynik.

Każdy wynik niesie `breakdown`: listę składników z wartością, wagą i wkładem, wersję
konfiguracji oraz zdanie „dlaczego” złożone przez kod z największych wkładów.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

COMPONENTS = ("cvss", "epss", "kev", "exposure", "criticality", "exploit")
LEVEL_ORDER = ("krytyczny", "wysoki", "średni", "niski")

_LABELS = {
    "cvss": "Wysoka ocena CVSS",
    "epss": "Wysokie prawdopodobieństwo wykorzystania (EPSS)",
    "kev": "Aktywnie wykorzystywana (KEV)",
    "exposure": "Dostępna z internetu",
    "criticality": "Ważny zasób",
    "exploit": "Publiczny exploit",
}


@dataclass(frozen=True)
class ScoringConfig:
    version: str
    weights: dict[str, float]
    exposure_values: dict[str, float]
    levels: dict[str, float]
    severity_values: dict[str, float]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScoringConfig:
        weights = {k: float(v) for k, v in (data.get("weights") or {}).items()}
        if set(weights) != set(COMPONENTS):
            raise ValueError(f"Wagi muszą obejmować dokładnie: {', '.join(COMPONENTS)}")
        if any(w < 0 for w in weights.values()) or not math.isclose(sum(weights.values()), 1.0):
            raise ValueError("Wagi muszą być nieujemne i sumować się do 1")
        levels = {k: float(v) for k, v in (data.get("levels") or {}).items()}
        if set(levels) != set(LEVEL_ORDER):
            raise ValueError(f"Poziomy muszą obejmować dokładnie: {', '.join(LEVEL_ORDER)}")
        thresholds = [levels[name] for name in LEVEL_ORDER]
        if thresholds != sorted(thresholds, reverse=True) or levels["niski"] != 0:
            raise ValueError("Progi poziomów muszą maleć, a próg „niski” musi wynosić 0")
        exposure = {k: float(v) for k, v in (data.get("exposure_values") or {}).items()}
        if set(exposure) != {"internet", "internal"}:
            raise ValueError("exposure_values musi zawierać internet i internal")
        return cls(
            version=str(data.get("version", "")),
            weights=weights,
            exposure_values=exposure,
            levels=levels,
            severity_values={k: float(v) for k, v in (data.get("severity_values") or {}).items()},
        )

    @classmethod
    def from_file(cls, path: Path) -> ScoringConfig:
        return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")) or {})

    def level_for(self, score: float) -> str:
        for name in LEVEL_ORDER:
            if score >= self.levels[name]:
                return name
        return "niski"


@dataclass(frozen=True)
class RiskInputs:
    exposure: str
    criticality: int
    cvss: float | None = None
    epss: float | None = None
    in_kev: bool = False
    has_public_exploit: bool = False
    # Dla findingów bez CVE: critical / high / medium / low zamiast CVSS.
    severity: str | None = None


@dataclass(frozen=True)
class Premium:
    """Premia za łańcuch ataku: nazwa reguły i liczba punktów."""

    rule: str
    points: float
    description: str = ""


@dataclass(frozen=True)
class RiskResult:
    score: float
    level: str
    breakdown: dict[str, Any] = field(default_factory=dict)


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


def score_risk(
    inputs: RiskInputs, config: ScoringConfig, premiums: tuple[Premium, ...] = ()
) -> RiskResult:
    if inputs.cvss is not None:
        cvss_value, cvss_source = _clamp(inputs.cvss * 10.0), f"CVSS {inputs.cvss:.1f}"
    elif inputs.severity is not None and inputs.severity in config.severity_values:
        cvss_value = _clamp(config.severity_values[inputs.severity])
        cvss_source = f"waga reguły: {inputs.severity}"
    else:
        cvss_value, cvss_source = 0.0, "brak oceny CVSS"
    if not 1 <= inputs.criticality <= 5:
        raise ValueError("Krytyczność zasobu musi być w zakresie 1–5")
    if inputs.exposure not in config.exposure_values:
        raise ValueError(f"Nieznana ekspozycja: {inputs.exposure}")

    values: dict[str, tuple[float, str]] = {
        "cvss": (cvss_value, cvss_source),
        "epss": (
            _clamp((inputs.epss or 0.0) * 100.0),
            f"EPSS {inputs.epss:.3f}" if inputs.epss is not None else "brak danych EPSS",
        ),
        "kev": (100.0 if inputs.in_kev else 0.0, "w katalogu KEV" if inputs.in_kev else "poza KEV"),
        "exposure": (
            config.exposure_values[inputs.exposure],
            "internet" if inputs.exposure == "internet" else "sieć wewnętrzna",
        ),
        "criticality": (
            (inputs.criticality - 1) / 4.0 * 100.0,
            f"krytyczność {inputs.criticality}/5",
        ),
        "exploit": (
            100.0 if inputs.has_public_exploit else 0.0,
            "znany exploit" if inputs.has_public_exploit else "brak znanego exploita",
        ),
    }
    components: list[dict[str, Any]] = []
    base = 0.0
    for name in COMPONENTS:
        value, source = values[name]
        weight = config.weights[name]
        contribution = round(value * weight, 2)
        base += contribution
        components.append(
            {
                "name": name,
                "label": _LABELS[name],
                "source": source,
                "value": round(value, 2),
                "weight": weight,
                "contribution": contribution,
            }
        )
    premium_total = sum(p.points for p in premiums)
    score = round(_clamp(base + premium_total), 1)
    level = config.level_for(score)

    reasons = [
        c["label"]
        for c in sorted(components, key=lambda c: (-c["contribution"], COMPONENTS.index(c["name"])))
        if _is_notable(c)
    ][:3]
    reasons += [p.description or p.rule for p in premiums]
    summary = f"{level.capitalize()}, bo: {' + '.join(reasons)}" if reasons else level.capitalize()

    return RiskResult(
        score=score,
        level=level,
        breakdown={
            "config_version": config.version,
            "components": components,
            "base_score": round(base, 2),
            "premiums": [
                {"rule": p.rule, "points": p.points, "description": p.description} for p in premiums
            ],
            "score": score,
            "level": level,
            "summary": summary,
        },
    )


def _is_notable(component: dict[str, Any]) -> bool:
    """Składnik trafia do zdania „dlaczego”, gdy jego wartość faktycznie podnosi ryzyko."""
    return float(component["value"]) >= 70.0 and float(component["contribution"]) > 0
