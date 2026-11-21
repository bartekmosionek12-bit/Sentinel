"""Filtrowanie wyników narzędzi, zanim zobaczy je agent (ARCHITECTURE §5.1).

Pełny wynik trafia do bazy. Agent dostaje ustrukturyzowany JSON bez sekretów i z krótkimi
polami tekstowymi. Wszystko, co napisał badany host (banery, tytuły stron), jest w kluczu
`untrusted` i w prompcie planisty jest oznaczone jako dane, nie polecenia.
"""

from __future__ import annotations

import re
from typing import Any

MAX_TEXT = 120
MAX_ITEMS = 50
_SECRET_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|ssh-ed25519-cert-v01@openssh\.com \S+|"
    r"SENTINEL-CANARY-[\w-]+|(?:password|passwd|secret|token)\s*[:=]\s*\S+)"
)


def scrub(text: str, limit: int = MAX_TEXT) -> str:
    cleaned = _SECRET_RE.sub("[usunięto]", " ".join(str(text).split()))
    return cleaned[:limit]


def _scrub_any(value: Any) -> Any:
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, list):
        return [_scrub_any(v) for v in value[:MAX_ITEMS]]
    if isinstance(value, dict):
        return {str(k)[:40]: _scrub_any(v) for k, v in list(value.items())[:MAX_ITEMS]}
    return value


def for_agent(result: dict[str, Any]) -> dict[str, Any]:
    """Kopia wyniku po usunięciu sekretów i skróceniu tekstów."""
    filtered: dict[str, Any] = _scrub_any(result)
    return filtered
