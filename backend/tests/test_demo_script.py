"""Moduł 22: scenariusz filmu demo (demo/script.yaml) mieści się w regułach.

Element podświetlany w każdej scenie sprawdza Playwright (frontend/e2e/demo.spec.ts).
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "demo_script", ROOT / "scripts" / "demo_script.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["demo_script"] = module  # dataclass szuka modułu w sys.modules
    spec.loader.exec_module(module)
    return module


DEMO = _module()


def test_script_fits_sixty_seconds_and_word_limits() -> None:
    script = DEMO.load()
    assert DEMO.problems(script) == []
    assert script["scenes"][-1]["end"] <= 60
    assert len(script["scenes"]) == 7


def test_every_scene_has_narration_and_subtitles() -> None:
    script = DEMO.load()
    cues = DEMO.cues(script)
    for scene in script["scenes"]:
        inside = [c for c in cues if scene["start"] <= c.start < scene["end"]]
        assert inside, scene["id"]
        assert inside[-1].end <= scene["end"]
    assert cues[-1].end <= 60
    assert DEMO.srt(script).startswith("1\n00:00:00,000 --> ")


def test_highlighted_elements_exist_in_frontend_sources() -> None:
    sources = "".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "frontend").glob("*/src/**/*.tsx")
    )
    for scene in DEMO.load()["scenes"]:
        for selector in (scene.get("highlight"), (scene.get("then") or {}).get("highlight")):
            if selector:
                name = selector.split('"')[1]
                assert f'data-demo="{name}"' in sources, (scene["id"], name)


def test_rules_catch_overlong_or_unsafe_scripts() -> None:
    script = DEMO.load()
    broken = copy.deepcopy(script)
    broken["scenes"][-1]["end"] = 75
    broken["scenes"][1]["narration"] = " ".join(["słowo"] * 60)
    broken["scenes"][2]["actions"] = ["rm_rf"]
    broken["scenes"][3]["highlight"] = "div.card"
    found = " ".join(DEMO.problems(broken))
    assert "limit to 60" in found
    assert "słowa na sekundę" in found
    assert "spoza listy" in found
    assert "data-demo" in found
