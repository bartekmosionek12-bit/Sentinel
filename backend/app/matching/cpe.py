"""Normalizacja nazwy produktu do pary producent i produkt w notacji CPE.

Kolejność: słownik aliasów (pewność 1.0), CPE podane przez narzędzie (1.0, jeśli taka
para istnieje w słowniku CPE), na końcu dopasowanie rozmyte `rapidfuzz` z wynikiem 0–1.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from rapidfuzz import fuzz, process

_NORMALIZE_RE = re.compile(r"[^a-z0-9.+]+")


def normalize_name(name: str) -> str:
    return _NORMALIZE_RE.sub(" ", name.lower()).strip()


@dataclass(frozen=True)
class CpeEntry:
    vendor: str
    product: str
    title: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.vendor, self.product)

    @property
    def cpe(self) -> str:
        return f"cpe:2.3:a:{self.vendor}:{self.product}"

    @property
    def search_texts(self) -> tuple[str, ...]:
        """Teksty do dopasowania rozmytego: nazwa z CPE oraz tytuł produktu."""
        from_cpe = " ".join(sorted({*self.vendor.split("_"), *self.product.split("_")}))
        from_title = " ".join(sorted(set(normalize_name(self.title).split())))
        return tuple(dict.fromkeys(text for text in (from_cpe, from_title) if text))


def parse_cpe(cpe: str) -> tuple[str, str, str | None] | None:
    """Zwraca (producent, produkt, wersja) dla formatów `cpe:/a:...` i `cpe:2.3:a:...`."""
    text = cpe.strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")[2:]
    elif text.startswith("cpe:/"):
        parts = text[5:].split(":")
    else:
        return None
    if len(parts) < 3 or not parts[1] or not parts[2]:
        return None
    version = parts[3] if len(parts) > 3 and parts[3] not in {"", "*", "-"} else None
    return parts[1], parts[2], version


@dataclass(frozen=True)
class MatchingConfig:
    auto: float = 0.90
    review: float = 0.60
    distro_penalty: float = 0.7

    @classmethod
    def from_file(cls, path: Path) -> MatchingConfig:
        data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        thresholds = data.get("thresholds") or {}
        config = cls(
            auto=float(thresholds.get("auto", 0.90)),
            review=float(thresholds.get("review", 0.60)),
            distro_penalty=float(data.get("distro_penalty", 0.7)),
        )
        if not 0 < config.review <= config.auto <= 1 or not 0 < config.distro_penalty <= 1:
            raise ValueError(f"{path}: nieprawidłowe progi dopasowania")
        return config


def load_aliases(path: Path) -> dict[str, CpeEntry]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    aliases: dict[str, CpeEntry] = {}
    for item in data.get("aliases") or []:
        entry = CpeEntry(str(item["vendor"]), str(item["product"]), str(item.get("title", "")))
        for name in item["names"]:
            key = normalize_name(str(name))
            if key in aliases and aliases[key].key != entry.key:
                raise ValueError(f"{path}: alias {name!r} wskazuje na dwa różne produkty")
            aliases[key] = entry
    return aliases


@dataclass(frozen=True)
class Candidate:
    entry: CpeEntry
    score: float
    method: str


@dataclass(frozen=True)
class Resolution:
    """Wynik normalizacji: najlepszy kandydat (lub brak) i lista alternatyw."""

    best: Candidate | None
    candidates: tuple[Candidate, ...] = field(default_factory=tuple)


class ProductNormalizer:
    def __init__(self, aliases: dict[str, CpeEntry], dictionary: Iterable[CpeEntry]) -> None:
        self._aliases = aliases
        entries = {entry.key: entry for entry in dictionary}
        for entry in aliases.values():
            entries.setdefault(entry.key, entry)
        self._entries = list(entries.values())
        self._known = set(entries)
        self._search: list[str] = []
        self._search_owner: list[int] = []
        for index, entry in enumerate(self._entries):
            for text in entry.search_texts:
                self._search.append(text)
                self._search_owner.append(index)

    def resolve(
        self, product: str, *, vendor: str = "", tool_cpes: Sequence[str] = (), limit: int = 3
    ) -> Resolution:
        name = normalize_name(product)
        full_name = normalize_name(f"{vendor} {product}") if vendor else name
        for key in (name, full_name):
            if key and key in self._aliases:
                candidate = Candidate(self._aliases[key], 1.0, "alias")
                return Resolution(candidate, (candidate,))
        for raw in tool_cpes:
            parsed = parse_cpe(raw)
            if parsed and (parsed[0], parsed[1]) in self._known:
                entry = next(e for e in self._entries if e.key == (parsed[0], parsed[1]))
                candidate = Candidate(entry, 1.0, "tool_cpe")
                return Resolution(candidate, (candidate,))
        if not full_name or not self._entries:
            return Resolution(None)
        query = " ".join(sorted(set(full_name.split())))
        found = process.extract(
            query, self._search, scorer=fuzz.token_sort_ratio, limit=limit * 2, score_cutoff=1
        )
        best_by_entry: dict[int, float] = {}
        for _text, score, index in found:
            owner = self._search_owner[index]
            best_by_entry[owner] = max(best_by_entry.get(owner, 0.0), score / 100.0)
        ranked = sorted(best_by_entry.items(), key=lambda item: (-item[1], item[0]))[:limit]
        candidates = tuple(
            Candidate(self._entries[index], round(score, 3), "fuzzy") for index, score in ranked
        )
        return Resolution(candidates[0] if candidates else None, candidates)
