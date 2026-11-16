"""Porównywanie wersji oprogramowania z zakresami podatnych wersji.

Obsługuje semver i schematy niestandardowe: `2.4.49`, `1.18.0`, `8.2p1`, `2.4.49-r1`,
`v1.2.3-beta2`, `2021.04`, `1.0.2k`. Zasada: jeżeli wersji nie da się wiarygodnie
porównać, zwracamy „nie wiem” (None), a nie zgadujemy.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass
from functools import total_ordering

_TOKEN_RE = re.compile(r"\d+|[a-z]+")
_VALID_RE = re.compile(r"^[0-9a-z][0-9a-z.+_~:-]*$")
# Pojedyncze litery (1.0.2a, 8.2p1) to sufiksy wydań, nie wersje przedpremierowe.
_PRE_RELEASE = {"dev": -5, "alpha": -4, "beta": -3, "pre": -2, "rc": -1}
_NUMERIC, _PRE, _TEXT = 1, 0, 2

# Sufiksy pakietów dystrybucji: poprawki bywają backportowane bez zmiany wersji upstream.
_DISTRO_RE = re.compile(
    r"(ubuntu|debian|\+deb\d+|~deb|\.el\d|\.fc\d|\.amzn|-r\d+$|\bsuse\b|alpine)", re.IGNORECASE
)

Key = tuple[tuple[int, int | str], ...]


@total_ordering
@dataclass(frozen=True)
class Version:
    raw: str
    key: Key

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return _padded(self.key, other.key) < _padded(other.key, self.key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return _padded(self.key, other.key) == _padded(other.key, self.key)

    def __hash__(self) -> int:
        return hash(_strip(self.key))


def _strip(key: Key) -> Key:
    end = len(key)
    while end > 0 and key[end - 1] == (_NUMERIC, 0):
        end -= 1
    return key[:end]


def _padded(key: Key, other: Key) -> Key:
    """Dopełnia zerami, żeby 1.2 == 1.2.0, a 1.2-rc1 < 1.2."""
    missing = len(other) - len(key)
    return key + ((_NUMERIC, 0),) * missing if missing > 0 else key


def parse_version(value: str | None) -> Version | None:
    """Zwraca wersję porównywalną albo None, gdy napisu nie da się zinterpretować."""
    if value is None:
        return None
    text = value.strip().lower()
    if text.startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    if ":" in text:  # epoka pakietu, np. 1:1.3.1
        epoch, _, rest = text.partition(":")
        if epoch.isdigit():
            text = rest
    if not text or text in {"*", "-"} or not _VALID_RE.match(text) or not text[0].isdigit():
        return None
    key: list[tuple[int, int | str]] = []
    for token in _TOKEN_RE.findall(text):
        if token.isdigit():
            key.append((_NUMERIC, int(token)))
        elif token in _PRE_RELEASE:
            key.append((_PRE, _PRE_RELEASE[token]))
        else:
            key.append((_TEXT, token))
    if not key:
        return None
    return Version(raw=value.strip(), key=tuple(key))


def is_distro_version(*texts: str | None) -> bool:
    """Czy wersja lub baner wskazuje na pakiet dystrybucji (możliwe backporty)."""
    return any(bool(_DISTRO_RE.search(text)) for text in texts if text)


@dataclass(frozen=True)
class VersionRange:
    exact: str | None = None
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    @property
    def is_unbounded(self) -> bool:
        return not any(
            (
                self.exact,
                self.start_including,
                self.start_excluding,
                self.end_including,
                self.end_excluding,
            )
        )

    def describe(self) -> str:
        if self.exact:
            return f"= {self.exact}"
        parts = []
        if self.start_including:
            parts.append(f">= {self.start_including}")
        if self.start_excluding:
            parts.append(f"> {self.start_excluding}")
        if self.end_including:
            parts.append(f"<= {self.end_including}")
        if self.end_excluding:
            parts.append(f"< {self.end_excluding}")
        return ", ".join(parts) or "wszystkie wersje"


def in_range(version: str | None, bounds: VersionRange) -> bool | None:
    """True/False, gdy da się rozstrzygnąć; None, gdy wersji albo granicy nie da się porównać."""
    if bounds.is_unbounded:
        return True
    parsed = parse_version(version)
    if parsed is None:
        return None
    if bounds.exact is not None:
        exact = parse_version(bounds.exact)
        return None if exact is None else parsed == exact
    checks: list[bool] = []
    for raw, compare in (
        (bounds.start_including, operator.ge),
        (bounds.start_excluding, operator.gt),
        (bounds.end_including, operator.le),
        (bounds.end_excluding, operator.lt),
    ):
        if raw is None:
            continue
        limit = parse_version(raw)
        if limit is None:
            return None
        checks.append(bool(compare(parsed, limit)))
    return all(checks)
