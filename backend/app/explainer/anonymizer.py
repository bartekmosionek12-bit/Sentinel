"""Anonimizacja tekstu przed wysłaniem do zewnętrznego modelu.

Nazwy zasobów z inwentarza zamieniamy na `asset_<id>`, a adresy IP, domeny i adresy
e-mail na znaczniki. Mapa odwrotna żyje wyłącznie w obiekcie `Anonymizer`, czyli
w pamięci procesu na czas jednego żądania; nigdzie nie jest zapisywana ani wysyłana.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.explainer.prompts import Prompt
from app.models import Asset

_SEAL: Final = object()
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\.?\w)")
_IPV6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w-])")
_TOKEN_RE = re.compile(r"\b(?:asset|owner|email|ip|domain)_[0-9a-f]{1,12}\b")
_MIN_NAME_LENGTH = 3


@dataclass(frozen=True)
class InventoryEntry:
    asset_id: str
    names: tuple[str, ...]
    owner: str | None = None


@dataclass(frozen=True)
class AnonymizedPrompt(Prompt):
    """Prompt po anonimizacji. Nie da się go utworzyć inaczej niż przez `Anonymizer`."""

    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("AnonymizedPrompt może wydać wyłącznie Anonymizer.anonymize()")


def inventory_entries(session: Session) -> list[InventoryEntry]:
    """Wszystkie napisy z inwentarza, które nie mogą opuścić maszyny."""
    entries = []
    for asset in session.scalars(select(Asset)):
        attributes = asset.attributes or {}
        names = [asset.name]
        for key in ("address", "hostname", "fqdn", "ip", "domain", "url"):
            value = attributes.get(key)
            if isinstance(value, str):
                names.append(value)
        for key in ("ips", "hostnames", "domains"):
            value = attributes.get(key)
            if isinstance(value, list):
                names.extend(str(v) for v in value)
        entries.append(
            InventoryEntry(
                asset_id=str(asset.id),
                names=tuple(dict.fromkeys(n.strip() for n in names if n and n.strip())),
                owner=asset.owner,
            )
        )
    return entries


class Anonymizer:
    def __init__(self, inventory: Iterable[InventoryEntry] = ()) -> None:
        self._forward: dict[str, str] = {}  # napis (małymi literami) → znacznik
        self._reverse: dict[str, str] = {}  # znacznik → oryginalny napis
        self._counters: dict[str, int] = {}
        literals: list[tuple[str, str]] = []
        for entry in inventory:
            token = f"asset_{entry.asset_id.replace('-', '')[:8]}"
            for name in entry.names:
                if len(name) >= _MIN_NAME_LENGTH:
                    literals.append((name, token))
                    # Znacznik zasobu wraca zawsze jako jego główna nazwa.
                    self._reverse.setdefault(token, name)
            if entry.owner and len(entry.owner.strip()) >= _MIN_NAME_LENGTH:
                literals.append((entry.owner.strip(), self._token("owner", entry.owner.strip())))
        # Najdłuższe napisy najpierw, żeby `web-01.firma.example` nie zostało jako
        # `asset_x.firma.example`.
        self._literals = sorted(literals, key=lambda item: len(item[0]), reverse=True)

    @property
    def replaced(self) -> int:
        """Liczba różnych napisów zamienionych na znaczniki (do audit logu)."""
        return len(self._reverse)

    def _token(self, kind: str, value: str) -> str:
        key = f"{kind}:{value.lower()}"
        if key not in self._forward:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            token = f"{kind}_{self._counters[kind]}"
            self._forward[key] = token
            self._reverse[token] = value
        return self._forward[key]

    def mask(self, text: str, *, keep: Sequence[str] = ()) -> str:
        """Maskuje tekst. `keep` to napisy publiczne (np. nazwa produktu), których nie ruszamy."""
        kept = {k.lower() for k in keep}
        for name, token in self._literals:
            if name.lower() in kept:
                continue
            text = re.sub(
                rf"(?<![\w-]){re.escape(name)}(?![\w-])", token, text, flags=re.IGNORECASE
            )

        def replace(kind: str, pattern: re.Pattern[str], value: str) -> str:
            def _sub(match: re.Match[str]) -> str:
                found = match.group(0)
                if found.lower() in kept or _TOKEN_RE.fullmatch(found):
                    return found
                return self._token(kind, found)

            return pattern.sub(_sub, value)

        text = replace("email", _EMAIL_RE, text)
        text = replace("ip", _IPV4_RE, text)
        text = replace("ip", _IPV6_RE, text)
        return replace("domain", _DOMAIN_RE, text)

    def anonymize(self, prompt: Prompt, *, keep: Sequence[str] = ()) -> AnonymizedPrompt:
        return AnonymizedPrompt(
            system=self.mask(prompt.system, keep=keep),
            user=self.mask(prompt.user, keep=keep),
            version=prompt.version,
            _seal=_SEAL,
        )

    def restore(self, text: str) -> str:
        """Przywraca oryginalne napisy w odpowiedzi modelu. Działa tylko lokalnie."""
        return _TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)
