"""Adapter nuclei: weryfikacja podatności szablonami wykrywającymi z jawnej listy (L2).

Bez eksploatacji: dozwolone są wyłącznie identyfikatory szablonów z `rules/nuclei.yaml`,
a tagi `intrusive`, `dos`, `fuzz`, `lfi`, `rce`, `sqli` i podobne są zawsze wykluczone.
Szablony wykrywające wersję pozwalają potwierdzić podatność porównaniem wersji, bez wysyłania
ładunku ataku. Szablony pobiera skrypt do obrazu `mcp-scanner`; nie ma ich w Gicie.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.core.scope_guard import Intrusiveness, ScopedTarget
from app.scanners.runner import SubprocessRunner, ToolError, ToolRunner

EXCLUDED_TAGS = ("intrusive", "dos", "fuzz", "lfi", "rce", "sqli", "xss", "exploit", "bruteforce")
_ID_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_")


@dataclass(frozen=True)
class NucleiConfig:
    templates_dir: str
    # CVE → identyfikatory szablonów wykrywających, które wolno uruchomić.
    templates: Mapping[str, tuple[str, ...]]
    rate_limit: int = 5

    @classmethod
    def from_file(cls, path: Path) -> NucleiConfig:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        templates: dict[str, tuple[str, ...]] = {}
        for cve, ids in (data.get("templates") or {}).items():
            clean = tuple(str(i) for i in ids)
            if any(not i or set(i) - _ID_CHARS for i in clean):
                raise ValueError(f"Nieprawidłowy identyfikator szablonu nuclei dla {cve}")
            templates[str(cve).upper()] = clean
        return cls(
            templates_dir=str(data.get("templates_dir", "/opt/nuclei-templates")),
            templates=templates,
            rate_limit=int(data.get("rate_limit", 5)),
        )


@dataclass(frozen=True)
class NucleiMatch:
    template_id: str
    name: str
    matched_at: str
    extracted: tuple[str, ...]


def parse_jsonl(output: str) -> list[NucleiMatch]:
    matches = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item: dict[str, Any] = json.loads(line)
        except ValueError as error:
            raise ToolError("nuclei: wynik nie jest JSON-em") from error
        info = item.get("info") or {}
        matches.append(
            NucleiMatch(
                template_id=str(item.get("template-id", "")),
                name=str(info.get("name", "")),
                matched_at=str(item.get("matched-at", "")),
                extracted=tuple(str(v) for v in item.get("extracted-results") or ()),
            )
        )
    return matches


class NucleiAdapter:
    binary = "nuclei"

    def __init__(self, config: NucleiConfig, runner: ToolRunner | None = None) -> None:
        self._config = config
        self._runner = runner or SubprocessRunner()

    def templates_for(self, cve_id: str) -> tuple[str, ...]:
        return self._config.templates.get(cve_id.upper(), ())

    def verify(
        self, target: ScopedTarget, *, cve_id: str, port: int, timeout: float = 180
    ) -> list[NucleiMatch]:
        if not isinstance(target, ScopedTarget):
            raise TypeError("nuclei.verify przyjmuje wyłącznie ScopedTarget")
        if target.intrusiveness < Intrusiveness.INTRUSIVE:
            raise ToolError("nuclei: weryfikacja podatności wymaga poziomu L2 i zgody")
        ids: Sequence[str] = self.templates_for(cve_id)
        if not ids:
            raise ToolError(f"nuclei: brak dozwolonego szablonu dla {cve_id}")
        args = [
            "-t", self._config.templates_dir,
            "-id", ",".join(ids),
            "-etags", ",".join(EXCLUDED_TAGS),
            "-rate-limit", str(self._config.rate_limit),
            "-disable-update-check",
            "-no-interactsh",
            "-jsonl",
            "-silent",
        ]  # fmt: skip
        output = self._runner.run(self.binary, args, target, timeout=timeout, port=port)
        return parse_jsonl(output.stdout)
