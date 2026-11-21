"""Moduł 22: scenariusz filmu demo (demo/script.yaml, 90 s) mieści się w regułach."""

from __future__ import annotations

import copy
import importlib.util
import re
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


def test_script_fits_time_and_word_limits() -> None:
    script = DEMO.load()
    assert DEMO.problems(script) == []
    assert script["scenes"][-1]["end"] <= script["max_seconds"] == 90


def test_every_scene_has_subtitles() -> None:
    script = DEMO.load()
    cues = DEMO.cues(script)
    for scene in script["scenes"]:
        inside = [c for c in cues if scene["start"] <= c.start < scene["end"]]
        assert inside, scene["id"]
    assert cues[-1].end <= script["max_seconds"]
    assert DEMO.srt(script).startswith("1\n00:00:0")


def test_highlighted_elements_exist_in_frontend_sources() -> None:
    sources = "".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "frontend").glob("*/src/**/*.tsx")
    )
    # Pola tworzone w pętli mają atrybut z szablonu, np. data-demo={`edit-${field}`}.
    prefixes = re.findall(r"data-demo=\{`([a-z-]+)\$\{", sources)
    for scene in DEMO.load()["scenes"]:
        for step in scene.get("steps") or []:
            selector = step.get("sel")
            if selector:
                name = selector.split('"')[1]
                found = f'data-demo="{name}"' in sources or any(map(name.startswith, prefixes))
                assert found, (scene["id"], name)


def test_rules_catch_overlong_or_unsafe_scripts() -> None:
    script = DEMO.load()
    broken = copy.deepcopy(script)
    broken["scenes"][-1]["end"] = 120
    broken["scenes"][1]["tts"] = " ".join(["słowo"] * 80)
    broken["scenes"][2]["steps"] = [{"at": 0.5, "do": "rm_rf"}]
    broken["scenes"][3]["steps"] = [{"at": 0.5, "do": "click", "sel": "div.card"}]
    found = " ".join(DEMO.problems(broken))
    assert "limit to 90" in found
    assert "słów na" in found
    assert "spoza listy" in found
    assert "data-demo" in found
