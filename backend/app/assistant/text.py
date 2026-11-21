"""Normalizacja tekstu i wyszukiwanie parametrów (urządzenie, dział, CVE, produkt, termin)."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from rapidfuzz import fuzz

CVE_RE = re.compile(r"\bcve[-\s_]?(\d{4})[-\s_]?(\d{4,7})\b", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
# Ograniczenie długości: pytanie do asystenta to jedno zdanie, nie dokument.
MAX_QUESTION_CHARS = 500


def normalize(text: str) -> str:
    """Małe litery bez polskich znaków: „Dział Finansów” → „dzial finansow”."""
    text = text.replace("ł", "l").replace("Ł", "L")
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return " ".join(stripped.lower().split())


def words(text: str) -> list[str]:
    return _WORD_RE.findall(normalize(text))


def find_cve(text: str) -> str | None:
    match = CVE_RE.search(text)
    return f"CVE-{match[1]}-{match[2]}" if match else None


def has_stem(tokens: Sequence[str], stems: Iterable[str]) -> int:
    """Ile rdzeni pasuje do słów pytania (prefiks albo literówka przy dłuższych słowach)."""
    hits = 0
    for stem in stems:
        if " " in stem:
            joined = " ".join(tokens)
            if stem in joined or (len(stem) >= 8 and fuzz.partial_ratio(stem, joined) >= 90):
                hits += 1
            continue
        for token in tokens:
            if token.startswith(stem) or (
                len(stem) >= 5 and len(token) >= 5 and fuzz.ratio(token[: len(stem)], stem) >= 85
            ):
                hits += 1
                break
    return hits


@dataclass(frozen=True)
class Named:
    """Rzecz z nazwą do odnalezienia w pytaniu (urządzenie, dział, produkt, termin)."""

    key: str
    name: str
    aliases: tuple[str, ...] = ()


def best_match(text: str, candidates: Iterable[Named], *, threshold: int = 88) -> Named | None:
    """Najlepiej pasująca nazwa. Krótkie nazwy (≤3 znaki) muszą być osobnym słowem."""
    norm = normalize(text)
    tokens = set(words(text))
    best: tuple[float, int, Named] | None = None
    for item in candidates:
        for raw in (item.name, *item.aliases):
            name = normalize(raw)
            if not name:
                continue
            if len(name) <= 3:
                score = 100.0 if name in tokens else 0.0
            elif re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", norm):
                score = 100.0
            elif len(name) >= 5:
                score = fuzz.partial_ratio(name, norm)
            else:
                score = 0.0
            if score >= threshold and (best is None or (score, len(name)) > best[:2]):
                best = (score, len(name), item)
    return best[2] if best else None
