"""Fakty o podatności dla modelu: składa je kod, z pól bazy i z plików reguł.

Kontekst jest wspólny dla wszystkich zasobów z danym CVE (zasada „generuj raz”),
więc nie zawiera żadnych danych o zasobach. Surowy wynik narzędzi nigdy tu nie trafia.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from app.explainer.guards import trusted_text
from app.matching.cpe import CpeEntry
from app.models import VulnAffected, Vulnerability
from app.models.ops import AUDIENCES

AUDIENCE_LABELS = {
    "technical": "techniczny",
    "operational": "operacyjny",
    "executive": "zarządczy",
}
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+[a-z]?")


@dataclass(frozen=True)
class AudienceLimits:
    max_tokens: int
    min_chars: int
    max_chars: int
    min_sentences: int
    max_sentences: int
    required_sections: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExplainerConfig:
    audiences: dict[str, AudienceLimits]
    verify_commands: dict[tuple[str, str], tuple[str, ...]]
    description_max_chars: int = 500
    # Zwroty bagatelizujące, które przeczą podatności z KEV albo o wysokiej wadze.
    downplaying: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExplainerConfig:
        audiences = {}
        for name in AUDIENCES:
            item = dict((data.get("audiences") or {})[name])
            sections = tuple(str(s) for s in item.pop("required_sections", ()))
            audiences[name] = AudienceLimits(
                **{k: int(v) for k, v in item.items()}, required_sections=sections
            )
        commands = {}
        for key, values in (data.get("verify_commands") or {}).items():
            vendor, _, product = str(key).partition(":")
            commands[(vendor, product)] = tuple(str(v) for v in values)
        return cls(
            audiences,
            commands,
            int(data.get("description_max_chars", 500)),
            tuple(" ".join(str(p).lower().split()) for p in data.get("downplaying") or ()),
        )

    @classmethod
    def from_file(cls, path: Path) -> ExplainerConfig:
        return cls.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


def severity_label(score: float | None) -> str:
    """Słowna waga wg progów CVSS v3."""
    if score is None:
        return "nieznana"
    if score >= 9.0:
        return "krytyczna"
    if score >= 7.0:
        return "wysoka"
    if score >= 4.0:
        return "średnia"
    return "niska"


def _range_text(row: VulnAffected) -> str:
    if row.version_exact:
        return f"wersja {row.version_exact}"
    parts = []
    if row.start_including:
        parts.append(f"od {row.start_including} włącznie")
    if row.start_excluding:
        parts.append(f"powyżej {row.start_excluding}")
    if row.end_including:
        parts.append(f"do {row.end_including} włącznie")
    if row.end_excluding:
        parts.append(f"poniżej {row.end_excluding}")
    return " ".join(parts) if parts else "wszystkie wersje"


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


@dataclass(frozen=True)
class ProductFacts:
    vendor: str
    product: str
    title: str
    ranges: tuple[str, ...]
    fixed_version: str | None
    commands: tuple[str, ...]


@dataclass(frozen=True)
class ExplainContext:
    cve_id: str
    description: str
    cvss_score: float | None
    epss: float | None
    in_kev: bool
    kev_due_date: date | None
    kev_required_action: str | None
    has_public_exploit: bool
    products: tuple[ProductFacts, ...]

    @property
    def severity(self) -> str:
        return severity_label(self.cvss_score)

    @property
    def fixed_versions(self) -> tuple[str, ...]:
        return tuple(p.fixed_version for p in self.products if p.fixed_version)

    @property
    def commands(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(c for p in self.products for c in p.commands))

    def facts_text(self) -> str:
        """Lista faktów przekazywana modelowi. Jedyne źródło wiedzy modelu."""
        lines = [f"- Identyfikator: {self.cve_id}"]
        for product in self.products:
            lines.append(f"- Produkt: {product.title}")
            lines.append(f"- Podatne wersje ({product.title}): {'; '.join(product.ranges)}")
            if product.fixed_version:
                lines.append(
                    f"- Wersja naprawiająca ({product.title}): {product.fixed_version} lub nowsza"
                )
            else:
                lines.append(
                    f"- Wersja naprawiająca ({product.title}): baza NVD jej nie podaje; "
                    "zalecana najnowsza wersja wskazana przez producenta"
                )
        if self.cvss_score is not None:
            lines.append(f"- Waga wg CVSS: {self.cvss_score:.1f} na 10 ({self.severity})")
        if self.in_kev:
            lines.append(
                "- Aktywnie wykorzystywana w atakach: tak (katalog CISA KEV znanych "
                "wykorzystywanych podatności)"
            )
            if self.kev_due_date:
                lines.append(f"- Termin usunięcia wg CISA KEV: {self.kev_due_date.isoformat()}")
            if self.kev_required_action:
                lines.append(f"- Działanie wymagane wg CISA KEV: {self.kev_required_action}")
        else:
            lines.append("- Aktywnie wykorzystywana w atakach: brak potwierdzenia w CISA KEV")
        if self.epss is not None:
            lines.append(
                f"- Szacowane prawdopodobieństwo wykorzystania w ciągu 30 dni (EPSS): "
                f"{round(self.epss * 100)}%"
            )
        lines.append(
            f"- Publicznie dostępny exploit: {'tak' if self.has_public_exploit else 'nie'}"
        )
        if self.commands:
            lines.append(
                "- Polecenia do sprawdzenia zainstalowanej wersji: "
                + ", ".join(f"`{c}`" for c in self.commands)
            )
        if self.description:
            lines.append(f"- Opis z bazy NVD (po angielsku): {self.description}")
        return "\n".join(lines)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.facts_text().encode("utf-8")).hexdigest()

    def allowed_versions(self) -> set[str]:
        """Numery z kropką, które model może przytoczyć: tylko te z faktów bez opisu CVE."""
        return set(_VERSION_RE.findall(trusted_text(self.facts_text())))

    def allowed_snippets(self) -> set[str]:
        """Teksty, które wolno umieścić w znakach kodu."""
        snippets = {self.cve_id.lower(), *(c.lower() for c in self.commands)}
        snippets |= {v.lower() for v in self.allowed_versions()}
        for product in self.products:
            snippets |= {product.title.lower(), product.product.lower(), product.vendor.lower()}
        return snippets


def build_context(
    vuln: Vulnerability,
    config: ExplainerConfig,
    titles: dict[tuple[str, str], str] | None = None,
) -> ExplainContext:
    titles = titles or {}
    grouped: dict[tuple[str, str], list[VulnAffected]] = {}
    for row in vuln.affected:
        grouped.setdefault((row.cpe_vendor, row.cpe_product), []).append(row)
    products = []
    for (vendor, product), rows in sorted(grouped.items()):
        fixes = sorted(
            {r.fixed_version or r.end_excluding for r in rows if r.fixed_version or r.end_excluding}
            - {None},
            key=lambda v: _version_key(str(v)),
        )
        products.append(
            ProductFacts(
                vendor=vendor,
                product=product,
                title=titles.get((vendor, product)) or product.replace("_", " "),
                ranges=tuple(dict.fromkeys(_range_text(r) for r in rows))[:6],
                # Najwyższa wersja naprawiająca usuwa podatność we wszystkich gałęziach.
                fixed_version=str(fixes[-1]) if fixes else None,
                commands=config.verify_commands.get((vendor, product), ()),
            )
        )
    description = " ".join((vuln.description or "").split())
    if len(description) > config.description_max_chars:
        description = description[: config.description_max_chars].rsplit(" ", 1)[0] + "…"
    return ExplainContext(
        cve_id=vuln.cve_id,
        description=description,
        cvss_score=vuln.cvss_score,
        epss=vuln.epss,
        in_kev=vuln.in_kev,
        kev_due_date=vuln.kev_due_date,
        kev_required_action=vuln.kev_required_action,
        has_public_exploit=vuln.has_public_exploit,
        products=tuple(products[:4]),
    )


def product_titles(aliases: dict[str, CpeEntry]) -> dict[tuple[str, str], str]:
    return {entry.key: entry.title for entry in aliases.values() if entry.title}
