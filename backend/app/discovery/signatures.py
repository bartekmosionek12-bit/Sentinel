"""Własne sygnatury detekcyjne (brief: R10, akapit o bezpiecznych sygnaturach).

Sygnatura opisuje tylko, czego SZUKAĆ w odpowiedzi, którą fingerprinter i tak pobiera
metodą GET. Nie da się w niej zapisać metody, treści żądania, poświadczeń ani parametrów:
walidator odrzuca każde nieznane pole. Typy dopasowań są dokładnie te z briefu:

  header        obecność nagłówka (opcjonalnie wartość pasująca do wzorca)
  cookie        nazwa ciasteczka
  favicon_hash  hash favicony (MurmurHash3 jak w Shodan)
  html          charakterystyczny fragment HTML
  title         tytuł strony
  generator     <meta name="generator"> (fingerprint CMS-a, wersja w stopce)
  path          ścieżka typu /login, /admin, /version: jedno żądanie GET, bez logowania,
                dopasowanie po kodzie odpowiedzi i (zalecane) fragmencie treści, bo aplikacje
                jednostronicowe zwracają 200 na każdą ścieżkę

Rodzaj sygnatury (`kind`): technology (lista technologii), panel albo staging (dowód do flagi).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

KINDS = {"technology", "panel", "staging"}
MATCH_TYPES = {"header", "cookie", "favicon_hash", "html", "title", "generator", "path"}
MAX_SIGNATURES = 200
MAX_PATHS = 10  # łącznie na usługę: więcej żądań to już nie „lekki” fingerprint
MAX_PATTERN = 200
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,99}$")
_MATCH_KEYS = {
    "header": {"type", "name", "pattern"},
    "cookie": {"type", "pattern"},
    "favicon_hash": {"type", "value"},
    "html": {"type", "pattern"},
    "title": {"type", "pattern"},
    "generator": {"type", "pattern"},
    "path": {"type", "path", "status", "pattern"},
}


class SignatureError(ValueError):
    """Sygnatura narusza zasady (zły typ, nieznane pole, niebezpieczna ścieżka)."""


@dataclass(frozen=True)
class Match:
    type: str
    pattern: re.Pattern[str] | None = None
    name: str = ""
    value: int | None = None
    path: str = ""
    status: tuple[int, ...] = ()


@dataclass(frozen=True)
class Signature:
    id: str
    name: str
    kind: str
    matches: tuple[Match, ...]
    description: str = ""


@dataclass
class Observed:
    """To, co fingerprinter już zebrał dla jednej usługi WWW."""

    headers: dict[str, str]
    cookies: list[str]
    body: str
    title: str
    generator: str
    favicon_hash: int | None
    paths: dict[str, int] = field(default_factory=dict)
    # Treść odpowiedzi na ścieżki z sygnatur: tylko do dopasowania, nigdzie nie zapisywana.
    path_bodies: dict[str, str] = field(default_factory=dict)


def _pattern(raw: Any, sid: str) -> re.Pattern[str]:
    if not isinstance(raw, str) or not raw or len(raw) > MAX_PATTERN:
        raise SignatureError(f"{sid}: wzorzec musi być tekstem do {MAX_PATTERN} znaków")
    try:
        return re.compile(raw, re.IGNORECASE)
    except re.error as error:
        raise SignatureError(f"{sid}: błędny wzorzec {raw!r}: {error}") from error


def _match(raw: Any, sid: str) -> Match:
    if not isinstance(raw, dict):
        raise SignatureError(f"{sid}: dopasowanie musi być słownikiem")
    kind = raw.get("type")
    if kind not in MATCH_TYPES:
        raise SignatureError(f"{sid}: typ dopasowania {kind!r} spoza {sorted(MATCH_TYPES)}")
    unknown = set(raw) - _MATCH_KEYS[kind]
    if unknown:
        raise SignatureError(f"{sid}: niedozwolone pola {sorted(unknown)} w dopasowaniu {kind}")
    if kind == "header":
        name = str(raw.get("name") or "").lower()
        if not re.fullmatch(r"[a-z0-9-]{1,64}", name):
            raise SignatureError(f"{sid}: zła nazwa nagłówka {name!r}")
        pattern = _pattern(raw["pattern"], sid) if "pattern" in raw else None
        return Match(type=kind, name=name, pattern=pattern)
    if kind == "favicon_hash":
        value = raw.get("value")
        if not isinstance(value, int) or isinstance(value, bool):
            raise SignatureError(f"{sid}: hash favicony musi być liczbą całkowitą")
        return Match(type=kind, value=value)
    if kind == "path":
        path = str(raw.get("path") or "")
        if not _PATH_RE.match(path) or ".." in path:
            raise SignatureError(
                f"{sid}: ścieżka {path!r} niedozwolona (tylko /ścieżka, bez parametrów i ..)"
            )
        status = raw.get("status") or [200]
        if not isinstance(status, list) or not all(
            isinstance(s, int) and 100 <= s <= 599 for s in status
        ):
            raise SignatureError(f"{sid}: status musi być listą kodów HTTP")
        pattern = _pattern(raw["pattern"], sid) if "pattern" in raw else None
        return Match(type=kind, path=path, status=tuple(status), pattern=pattern)
    return Match(type=kind, pattern=_pattern(raw.get("pattern"), sid))


def parse_signatures(data: Any) -> tuple[Signature, ...]:
    """Waliduje całą listę; jeden błąd odrzuca plik, żeby nie skanować z połową reguł."""
    items = (data or {}).get("signatures") or [] if isinstance(data, dict) else []
    if not isinstance(items, list):
        raise SignatureError("signatures musi być listą")
    if len(items) > MAX_SIGNATURES:
        raise SignatureError(f"najwyżej {MAX_SIGNATURES} sygnatur")
    out: list[Signature] = []
    seen: set[str] = set()
    for raw in items:
        if not isinstance(raw, dict):
            raise SignatureError("sygnatura musi być słownikiem")
        sid = str(raw.get("id") or "")
        if not _ID_RE.match(sid):
            raise SignatureError(f"zły identyfikator sygnatury {sid!r}")
        if sid in seen:
            raise SignatureError(f"{sid}: powtórzony identyfikator")
        seen.add(sid)
        unknown = set(raw) - {"id", "name", "kind", "description", "match"}
        if unknown:
            raise SignatureError(f"{sid}: niedozwolone pola {sorted(unknown)}")
        if raw.get("kind") not in KINDS:
            raise SignatureError(f"{sid}: rodzaj {raw.get('kind')!r} spoza {sorted(KINDS)}")
        matches = raw.get("match")
        if not isinstance(matches, list) or not matches:
            raise SignatureError(f"{sid}: potrzebne co najmniej jedno dopasowanie")
        out.append(
            Signature(
                id=sid,
                name=str(raw.get("name") or sid)[:80],
                kind=str(raw["kind"]),
                description=str(raw.get("description") or "")[:200],
                matches=tuple(_match(m, sid) for m in matches),
            )
        )
    paths = {m.path for s in out for m in s.matches if m.type == "path"}
    if len(paths) > MAX_PATHS:
        raise SignatureError(f"sygnatury proszą o {len(paths)} ścieżek, limit to {MAX_PATHS}")
    return tuple(out)


def load_signatures(path: Path) -> tuple[Signature, ...]:
    if not path.exists():
        return ()
    return parse_signatures(yaml.safe_load(path.read_text(encoding="utf-8")))


def signature_paths(signatures: tuple[Signature, ...]) -> list[str]:
    return list(dict.fromkeys(m.path for s in signatures for m in s.matches if m.type == "path"))


def _evidence(match: Match, seen: Observed) -> str | None:
    """Opis dowodu, jeśli dopasowanie zachodzi; inaczej None."""
    if match.type == "header":
        value = seen.headers.get(match.name)
        if value is None or (match.pattern and not match.pattern.search(value)):
            return None
        return f"nagłówek {match.name}"
    if match.type == "cookie":
        hit = next((c for c in seen.cookies if match.pattern and match.pattern.search(c)), None)
        return f"ciasteczko {hit}" if hit else None
    if match.type == "favicon_hash":
        return "hash favicony" if seen.favicon_hash == match.value else None
    if match.type == "path":
        code = seen.paths.get(match.path)
        if code not in match.status:
            return None
        if match.pattern and not match.pattern.search(seen.path_bodies.get(match.path, "")):
            return None
        return f"{match.path} → {code}"
    text = {"html": seen.body, "title": seen.title, "generator": seen.generator}[match.type]
    if text and match.pattern and match.pattern.search(text):
        return {"html": "fragment HTML", "title": "tytuł", "generator": "meta generator"}[
            match.type
        ]
    return None


def evaluate(signatures: tuple[Signature, ...], seen: Observed) -> list[dict[str, Any]]:
    """Trafione sygnatury z dowodami. Sygnatura trafia, gdy pasuje choć jedno dopasowanie."""
    hits: list[dict[str, Any]] = []
    for signature in signatures:
        evidence = [e for m in signature.matches if (e := _evidence(m, seen))]
        if evidence:
            hits.append(
                {
                    "id": signature.id,
                    "name": signature.name,
                    "kind": signature.kind,
                    "evidence": list(dict.fromkeys(evidence)),
                }
            )
    return hits
