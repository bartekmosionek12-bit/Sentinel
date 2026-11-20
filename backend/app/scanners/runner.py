"""Jedyne miejsce w systemie, które uruchamia zewnętrzne procesy skanujące.

Reguły:
* cel procesu to zawsze `ScopedTarget` albo `ScopedNetwork` wydany przez scope_guard,
* adres celu dopisuje ten moduł jako ostatni argument; adapter nie może podać innego,
* binarka musi być na liście dozwolonych, nie ma powłoki, jest limit czasu.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.core.scope_guard import ScopedNetwork, ScopedTarget

logger = logging.getLogger("sentinel.scanners")

# Narzędzie → sposób podania celu. Cel zawsze dopisuje runner, z adresu sprawdzonego przez bramę.
TARGET_STYLE = {"nmap": "positional", "nuclei": "flag"}
ALLOWED_BINARIES = frozenset(TARGET_STYLE)


class ToolError(Exception):
    """Narzędzie nie uruchomiło się, przekroczyło czas albo zwróciło błąd."""


@dataclass(frozen=True)
class ToolOutput:
    stdout: str
    stderr: str
    returncode: int
    argv: tuple[str, ...]


class ToolRunner(Protocol):
    def run(
        self,
        binary: str,
        args: Sequence[str],
        target: ScopedTarget | ScopedNetwork,
        *,
        timeout: float,
        port: int | None = None,
    ) -> ToolOutput: ...


def build_argv(
    binary: str,
    args: Sequence[str],
    target: ScopedTarget | ScopedNetwork,
    *,
    port: int | None = None,
) -> tuple[str, ...]:
    if not isinstance(target, ScopedTarget | ScopedNetwork):
        raise TypeError(
            "Runner przyjmuje wyłącznie cel wydany przez scope_guard, "
            f"otrzymano {type(target).__name__}"
        )
    if binary not in ALLOWED_BINARIES:
        raise ToolError(f"Narzędzie {binary!r} nie jest na liście dozwolonych")
    for arg in args:
        if not isinstance(arg, str) or "\x00" in arg or "\n" in arg:
            raise ToolError("Nieprawidłowy argument narzędzia")
    if TARGET_STYLE[binary] == "flag":
        # nuclei: `-u <ip>:<port>`; port to liczba sprawdzona tutaj, adres z bramy.
        if not isinstance(target, ScopedTarget):
            raise ToolError(f"{binary} przyjmuje wyłącznie pojedynczy cel")
        if port is None or not 1 <= int(port) <= 65535:
            raise ToolError(f"{binary}: wymagany poprawny port celu")
        host = f"[{target.address}]" if ":" in target.address else target.address
        return (binary, *args, "-u", f"{host}:{int(port)}")
    return (binary, *args, "--", target.address)


class SubprocessRunner:
    def run(
        self,
        binary: str,
        args: Sequence[str],
        target: ScopedTarget | ScopedNetwork,
        *,
        timeout: float,
        port: int | None = None,
    ) -> ToolOutput:
        argv = build_argv(binary, args, target, port=port)
        executable = shutil.which(binary)
        if executable is None:
            raise ToolError(f"Brak narzędzia {binary} w tym kontenerze")
        logger.info("tool_start", extra={"tool": binary, "target": target.address})
        try:
            completed = subprocess.run(  # noqa: S603 - argv z listy, bez powłoki
                (executable, *argv[1:]),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ToolError(f"{binary}: przekroczony limit czasu {timeout:.0f} s") from error
        except OSError as error:
            raise ToolError(f"{binary}: nie udało się uruchomić ({error})") from error
        if completed.returncode != 0:
            raise ToolError(
                f"{binary}: kod wyjścia {completed.returncode}: {completed.stderr.strip()[:300]}"
            )
        return ToolOutput(completed.stdout, completed.stderr, completed.returncode, argv)
