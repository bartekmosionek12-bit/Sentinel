"""Prompty wersjonowane w plikach `<nazwa>.v<N>.md`.

Zmiana treści promptu oznacza nowy plik z wyższą wersją, a więc nowy klucz cache.
Plik ma dwie sekcje: `## SYSTEM` i `## USER`; w drugiej `{{facts}}` zastępują fakty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PROMPTS_DIR = Path(__file__).parent
_FILE_RE = re.compile(r"^(?P<name>[a-z_]+)\.v(?P<version>\d+)\.md$")
FACTS_PLACEHOLDER = "{{facts}}"


@dataclass(frozen=True)
class Prompt:
    system: str
    user: str
    version: str


@dataclass(frozen=True)
class PromptTemplate:
    version: str
    system: str
    user: str

    def render(self, facts: str) -> Prompt:
        return Prompt(self.system, self.user.replace(FACTS_PLACEHOLDER, facts), self.version)


@lru_cache
def load_template(name: str) -> PromptTemplate:
    """Zwraca najnowszą wersję promptu o podanej nazwie."""
    versions = {}
    for path in PROMPTS_DIR.glob(f"{name}.v*.md"):
        match = _FILE_RE.match(path.name)
        if match and match["name"] == name:
            versions[int(match["version"])] = path
    if not versions:
        raise FileNotFoundError(f"Brak promptu {name!r} w {PROMPTS_DIR}")
    number = max(versions)
    text = versions[number].read_text(encoding="utf-8")
    _, _, rest = text.partition("## SYSTEM")
    system, marker, user = rest.partition("## USER")
    if not marker or FACTS_PLACEHOLDER not in user:
        raise ValueError(f"{versions[number].name}: wymagane sekcje SYSTEM i USER z {{{{facts}}}}")
    return PromptTemplate(f"{name}.v{number}", system.strip(), user.strip())
