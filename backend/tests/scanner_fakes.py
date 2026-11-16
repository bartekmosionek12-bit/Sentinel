"""Fałszywy runner narzędzi: zwraca przygotowany XML i zapisuje wywołania."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from app.core.scope_guard import ScopedNetwork, ScopedTarget
from app.scanners.runner import ToolOutput, build_argv

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeRunner:
    def __init__(self, respond: Callable[[tuple[str, ...]], str]) -> None:
        self._respond = respond
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        binary: str,
        args: Sequence[str],
        target: ScopedTarget | ScopedNetwork,
        *,
        timeout: float,
    ) -> ToolOutput:
        argv = build_argv(binary, args, target)
        self.calls.append(argv)
        return ToolOutput(self._respond(argv), "", 0, argv)
