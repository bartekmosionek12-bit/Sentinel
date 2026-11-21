#!/usr/bin/env bash
# Moduł 22: lektor z lokalnego syntezatora Piper (bez chmury, bez klonowania głosu).
#
#   ./scripts/demo_tts.sh     # demo/out/audio/<scena>.wav z narracji w demo/script.yaml
#
# Głos: pl_PL-darkman-medium. Według dokumentacji Pipera (docs/COMMERCIAL_USE.md w
# OHF-Voice/piper1-gpl) głosy dostrajane z bazy „lessac” mają licencję tylko do badań, a
# darkman jest na liście głosów przetrenowanych na nowej bazie, z danymi CC0. Liczy się
# pobrana kopia: skrypt odmawia, jeśli MODEL_CARD nadal mówi „Finetuned from … lessac”.
# Silnik Piper (GPL-3.0) instalujemy w osobnym środowisku demo/.venv-tts; nie jest częścią
# produktu. Nie klonujemy głosu żadnej realnej osoby.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON=${PYTHON:-backend/.venv/bin/python}
VOICE=${VOICE:-pl_PL-darkman-medium}
# Tempo: <1 to szybciej (domyślnie lekko szybciej niż wzorzec głosu, żeby zmieścić scenę).
LENGTH_SCALE=${LENGTH_SCALE:-0.92}
PIPER_VERSION=1.8.0
BASE=https://huggingface.co/rhasspy/piper-voices/resolve/main/pl/pl_PL/darkman/medium
MODELS=demo/.models
VENV=demo/.venv-tts
OUT=demo/out/audio

mkdir -p "$MODELS" "$OUT"
if [ ! -x "$VENV/bin/piper" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet "piper-tts==$PIPER_VERSION"
fi
for file in "$VOICE.onnx" "$VOICE.onnx.json" MODEL_CARD; do
  [ -s "$MODELS/$file" ] || curl -fsSL --retry 3 -o "$MODELS/$file" "$BASE/$file"
done
if grep -qi "lessac" "$MODELS/MODEL_CARD"; then
  echo "Pobrany głos $VOICE jest jeszcze dostrojony z bazy lessac (licencja tylko do badań)." >&2
  echo "Nie generuję lektora do publicznego filmu. Szczegóły: docs/DEMO_GUIDE.md, „Lektor”." >&2
  exit 1
fi
echo "Głos: $VOICE, sha256: $(sha256sum "$MODELS/$VOICE.onnx" | cut -d' ' -f1)"
grep -E "License|Finetuned" "$MODELS/MODEL_CARD" || true

"$PYTHON" scripts/demo_script.py lines | while IFS=$'\t' read -r id text; do
  printf '%s\n' "$text" | "$VENV/bin/piper" --model "$MODELS/$VOICE.onnx" --length-scale "$LENGTH_SCALE" --output_file "$OUT/$id.wav" >/dev/null
done

# Lektor sceny nie może być dłuższy niż scena.
"$PYTHON" - <<'PY'
import json, subprocess, sys, wave
script = json.loads(subprocess.check_output([sys.executable, "scripts/demo_script.py", "json"]))
bad = 0
for scene in script["scenes"]:
    with wave.open(f"demo/out/audio/{scene['id']}.wav") as audio:
        seconds = audio.getnframes() / audio.getframerate()
    limit = scene["end"] - scene["start"]
    mark = "OK" if seconds <= limit else "ZA DŁUGO"
    bad += seconds > limit
    print(f"{scene['id']:<18} {seconds:5.1f} s / {limit} s  {mark}")
sys.exit(1 if bad else 0)
PY
