"""Test architektury: dostęp do sieci i procesów tylko z jawnie wymienionych modułów.

Jeżeli ten test nie przechodzi, nowy kod próbuje sięgnąć do sieci albo uruchomić
proces z pominięciem `scope_guard`. Dopisanie pliku do listy wymaga uzasadnienia
w recenzji: moduł musi przyjmować wyłącznie `ScopedTarget` (skanowanie) albo
łączyć się wyłącznie ze stałą listą hostów (feedy, powiadomienia, LLM).
"""

from __future__ import annotations

import ast
from pathlib import Path

APP_DIR = Path(__file__).resolve().parents[1] / "app"

# moduł → pliki (względem backend/app), które mogą go importować
ALLOWED: dict[str, set[str]] = {
    "socket": {"core/scope_guard.py"},
    "subprocess": {"scanners/runner.py"},
    "asyncio.subprocess": {"scanners/runner.py"},
    "httpx": {
        "feeds/http.py",
        "notifications/channels.py",
        "explainer/providers.py",
        "iam/jwks.py",
    },
    "requests": set(),
    "aiohttp": set(),
    "urllib.request": set(),
    "urllib3": set(),
    "http.client": set(),
    "ftplib": set(),
    "telnetlib": set(),
    "smtplib": {"notifications/channels.py"},
    "paramiko": set(),
    "scapy": set(),
    "nmap": set(),
    "pty": set(),
}
FORBIDDEN_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "spawnv"),
    ("asyncio", "create_subprocess_exec"),
    ("asyncio", "create_subprocess_shell"),
    ("asyncio", "open_connection"),
}
CALLS_ALLOWED_IN = {"scanners/runner.py"}


def _restricted(module: str) -> str | None:
    for name in ALLOWED:
        if module == name or module.startswith(name + "."):
            return name
    return None


def _violations() -> list[str]:
    problems: list[str] = []
    for path in sorted(APP_DIR.rglob("*.py")):
        relative = path.relative_to(APP_DIR).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 0)
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for module in modules:
                name = _restricted(module)
                if name and relative not in ALLOWED[name]:
                    problems.append(f"{relative}:{lineno} importuje {module}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and (node.func.value.id, node.func.attr) in FORBIDDEN_CALLS
                and relative not in CALLS_ALLOWED_IN
            ):
                problems.append(
                    f"{relative}:{lineno} wywołuje {node.func.value.id}.{node.func.attr}"
                )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"__import__", "eval", "exec"}
            ):
                problems.append(f"{relative}:{lineno} używa {node.func.id}()")
    return problems


def test_network_and_process_access_only_from_allowed_modules() -> None:
    assert _violations() == []


def test_detector_catches_a_bypass(tmp_path: Path, monkeypatch: object) -> None:
    """Sprawdza sam detektor: plik sięgający do sieci musi zostać wykryty."""
    import tests.test_architecture as module

    rogue = tmp_path / "inventory"
    rogue.mkdir()
    (rogue / "sneaky.py").write_text(
        "import subprocess\nfrom socket import create_connection\nimport os\n"
        "def run(t):\n    os.system('nmap ' + t)\n",
        encoding="utf-8",
    )
    original = module.APP_DIR
    module.APP_DIR = tmp_path
    try:
        found = module._violations()
    finally:
        module.APP_DIR = original
    assert len(found) == 4
    assert any("subprocess" in f for f in found)
    assert any("socket" in f for f in found)
    assert any("os.system" in f for f in found)
