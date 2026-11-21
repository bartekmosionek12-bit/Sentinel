#!/usr/bin/env python3
"""Scenariusz filmu demo (moduł 22): walidacja, napisy .srt i plan nagrania z demo/script.yaml.

    python3 scripts/demo_script.py check              # reguły scenariusza
    python3 scripts/demo_script.py json  > out.json   # scenariusz dla nagrywarki
    python3 scripts/demo_script.py srt   > demo.srt   # napisy z pola `subtitle`
    python3 scripts/demo_script.py lines              # „id<TAB>tts” dla lektora

Napisy: jeśli istnieje demo/out/audio/durations.json (zapisuje go demo_tts.sh), plansze
napisów rozkładamy na faktyczną długość lektora w scenie; inaczej na całą scenę.
Potrzebuje PyYAML (jest w środowisku backendu: backend/.venv/bin/python).
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "demo" / "script.yaml"
DURATIONS = ROOT / "demo" / "out" / "audio" / "durations.json"
# Akcje, które umie wykonać nagrywarka (frontend/scripts/record-demo.mjs). Nic spoza listy.
STEP_ACTIONS = frozenset({"highlight", "click", "fill", "upload", "check", "goto", "defectdojo"})
POSES = frozenset({"idle", "talk", "wave", "point_left", "point_right", "surprised", "thumbs_up"})
# Napis: najwyżej tyle słów na jedną planszę (dwie linie po ok. 42 znaki).
WORDS_PER_CUE = 9
# Lektor zaczyna chwilę po początku sceny (oddech między scenami).
LEAD_SECONDS = 0.3


@dataclass(frozen=True)
class Cue:
    start: float
    end: float
    text: str


def load(path: Path = SCRIPT) -> dict[str, Any]:
    return dict(yaml.safe_load(path.read_text(encoding="utf-8")))


def words(text: str) -> int:
    return len(text.split())


def problems(script: dict[str, Any]) -> list[str]:
    """Lista naruszeń reguł scenariusza; pusta = scenariusz poprawny."""
    out: list[str] = []
    scenes = script.get("scenes") or []
    if not scenes:
        return ["brak scen"]
    limit = float(script["max_seconds"])
    rate = float(script["max_words_per_second"])
    previous_end = 0.0
    ids: set[str] = set()
    for scene in scenes:
        sid = str(scene.get("id"))
        if sid in ids:
            out.append(f"{sid}: powtórzony identyfikator")
        ids.add(sid)
        start, end = float(scene["start"]), float(scene["end"])
        if start != previous_end:
            out.append(f"{sid}: zaczyna się w {start} s, poprzednia kończy w {previous_end} s")
        if end <= start:
            out.append(f"{sid}: koniec nie jest po początku")
        previous_end = end
        for field in ("subtitle", "tts"):
            if not str(scene.get(field) or "").strip():
                out.append(f"{sid}: brak pola {field}")
        tts = str(scene.get("tts") or "")
        if re.search(r"\d", tts):
            out.append(f"{sid}: w tts liczby zapisujemy słownie")
        if tts and words(tts) / (end - start) > rate:
            out.append(f"{sid}: {words(tts)} słów na {end - start:.0f} s, ponad {rate} słowa/s")
        if scene.get("pose") not in POSES:
            out.append(f"{sid}: nieznana poza Sentka {scene.get('pose')!r}")
        for step in scene.get("steps") or []:
            action = step.get("do")
            if action not in STEP_ACTIONS:
                out.append(f"{sid}: akcja {action!r} spoza listy {sorted(STEP_ACTIONS)}")
            if not 0 <= float(step.get("at", -1)) < end - start:
                out.append(f"{sid}: krok {action} poza czasem sceny")
            selector = step.get("sel")
            if selector and "data-demo" not in selector:
                out.append(f"{sid}: selektor tylko przez atrybut data-demo, nie {selector!r}")
            if action == "upload" and not (ROOT / str(step.get("file"))).is_file():
                out.append(f"{sid}: brak pliku {step.get('file')}")
    if previous_end > limit:
        out.append(f"film trwa {previous_end} s, limit to {limit} s")
    total = sum(words(str(s.get("tts") or "")) for s in scenes)
    if total > int(script["max_words"]):
        out.append(f"lektor ma {total} słów, limit to {script['max_words']}")
    if not any(s.get("end_card") for s in scenes):
        out.append("brak planszy końcowej")
    return out


def _durations() -> dict[str, float]:
    try:
        return {str(k): float(v) for k, v in json.loads(DURATIONS.read_text()).items()}
    except (OSError, ValueError):
        return {}


def cues(script: dict[str, Any]) -> list[Cue]:
    """Plansze napisów: tekst sceny dzielony po słowach, czas proporcjonalnie do słów."""
    out: list[Cue] = []
    spoken = _durations()
    for scene in script["scenes"]:
        start, end = float(scene["start"]), float(scene["end"])
        tokens = str(scene["subtitle"]).split()
        # Nowa plansza po kropce albo po WORDS_PER_CUE słowach (zdanie nie skacze w połowie,
        # o ile się mieści).
        chunks: list[list[str]] = [[]]
        for token in tokens:
            if len(chunks[-1]) >= WORDS_PER_CUE or (chunks[-1] and chunks[-1][-1].endswith(".")):
                chunks.append([])
            chunks[-1].append(token)
        merged: list[list[str]] = []
        for chunk in chunks:
            if merged and len(chunk) < 3:
                merged[-1].extend(chunk)
            else:
                merged.append(chunk)
        chunks = merged
        if scene["id"] in spoken:
            at = start + LEAD_SECONDS
            span = min(end - at, spoken[scene["id"]] + 0.4)
        else:
            at, span = start, end - start
        for chunk in chunks:
            length = span * len(chunk) / len(tokens)
            out.append(Cue(round(at, 2), round(min(end, at + length), 2), " ".join(chunk)))
            at += length
    return out


def _stamp(seconds: float) -> str:
    millis = round(seconds * 1000)
    hours, millis = divmod(millis, 3_600_000)
    minutes, millis = divmod(millis, 60_000)
    secs, millis = divmod(millis, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"


def srt(script: dict[str, Any]) -> str:
    blocks = [
        f"{index}\n{_stamp(cue.start)} --> {_stamp(cue.end)}\n{cue.text}\n"
        for index, cue in enumerate(cues(script), start=1)
    ]
    return "\n".join(blocks)


def main(argv: list[str]) -> int:
    command = argv[1] if len(argv) > 1 else "check"
    script = load()
    found = problems(script)
    if command == "check":
        for problem in found:
            print(f"BŁĄD: {problem}", file=sys.stderr)
        total = sum(words(str(s["tts"])) for s in script["scenes"])
        end = script["scenes"][-1]["end"]
        print(f"Scen: {len(script['scenes'])}, czas: {end} s, słów lektora: {total}")
        return 1 if found else 0
    if found:
        print("Scenariusz ma błędy, uruchom: python3 scripts/demo_script.py check", file=sys.stderr)
        return 1
    if command == "json":
        print(json.dumps(script, ensure_ascii=False))
    elif command == "srt":
        print(srt(script), end="")
    elif command == "lines":
        for scene in script["scenes"]:
            print(f"{scene['id']}\t{scene['tts']}\t{scene.get('tts_length_scale', '')}")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
