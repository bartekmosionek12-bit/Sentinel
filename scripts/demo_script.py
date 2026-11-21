#!/usr/bin/env python3
"""Scenariusz filmu demo (moduł 22): walidacja, napisy .srt i plan montażu z demo/script.yaml.

    python3 scripts/demo_script.py check              # reguły scenariusza (jak test w CI)
    python3 scripts/demo_script.py json  > out.json   # scenariusz dla nagrywarki
    python3 scripts/demo_script.py srt   > demo.srt   # napisy z narracji
    python3 scripts/demo_script.py lines              # „id<TAB>narracja” dla lektora

Potrzebuje PyYAML (jest w środowisku backendu: backend/.venv/bin/python).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "demo" / "script.yaml"
# Akcje, które nagrywarka umie wykonać (scripts/record_demo.mjs). Nic spoza listy.
ACTIONS = frozenset({"inject_kev", "open_latest_report"})
POSES = frozenset({"idle", "talk", "wave", "point_left", "point_right", "surprised", "thumbs_up"})
APPS = frozenset({"dashboard", "admin"})
# Napis: najwyżej tyle słów na jedną planszę (dwie linie po ok. 42 znaki).
WORDS_PER_CUE = 9


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
        narration = str(scene.get("narration") or "").strip()
        if not narration:
            out.append(f"{sid}: brak narracji (lektor i napisy)")
        elif words(narration) / (end - start) > rate:
            out.append(
                f"{sid}: {words(narration)} słów na {end - start:.0f} s, "
                f"ponad {rate} słowa na sekundę"
            )
        if scene.get("app") not in APPS:
            out.append(f"{sid}: nieznana aplikacja {scene.get('app')!r}")
        if scene.get("pose") not in POSES:
            out.append(f"{sid}: nieznana poza Sentka {scene.get('pose')!r}")
        for action in scene.get("actions") or []:
            if action not in ACTIONS:
                out.append(f"{sid}: akcja {action!r} spoza listy {sorted(ACTIONS)}")
        for selector in (scene.get("highlight"), (scene.get("then") or {}).get("highlight")):
            if selector and "data-demo" not in selector:
                out.append(f"{sid}: podświetlenie tylko przez atrybut data-demo, nie {selector!r}")
        then = scene.get("then")
        if then and not 0 < float(then["at"]) < end - start:
            out.append(f"{sid}: „then.at” poza czasem sceny")
    if previous_end > limit:
        out.append(f"film trwa {previous_end} s, limit to {limit} s")
    total = sum(words(str(s.get("narration") or "")) for s in scenes)
    if total > int(script["max_words"]):
        out.append(f"narracja ma {total} słów, limit to {script['max_words']}")
    if not any(s.get("end_card") for s in scenes):
        out.append("brak planszy końcowej")
    return out


def cues(script: dict[str, Any]) -> list[Cue]:
    """Napisy: narracja każdej sceny dzielona na plansze, czas proporcjonalnie do słów."""
    out: list[Cue] = []
    for scene in script["scenes"]:
        start, end = float(scene["start"]), float(scene["end"])
        tokens = str(scene["narration"]).split()
        chunks = [tokens[i : i + WORDS_PER_CUE] for i in range(0, len(tokens), WORDS_PER_CUE)]
        # Ostatnia krótka plansza dołącza do poprzedniej.
        if len(chunks) > 1 and len(chunks[-1]) < 3:
            chunks[-2].extend(chunks.pop())
        span = end - start
        at = start
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
        total = sum(words(str(s["narration"])) for s in script["scenes"])
        end = script["scenes"][-1]["end"]
        print(f"Scen: {len(script['scenes'])}, czas: {end} s, słów: {total}")
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
            print(f"{scene['id']}\t{scene['narration']}")
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
