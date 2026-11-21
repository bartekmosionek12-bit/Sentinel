#!/usr/bin/env bash
# Moduł 22: montaż filmu z klipów (record_demo.sh) i lektora (demo_tts.sh).
#
#   ./scripts/assemble_demo.sh            # demo/out/demo.mp4 i demo/out/demo.srt
#   NO_AUDIO=1 ./scripts/assemble_demo.sh # bez lektora (cisza), np. do próby
#
# Każda scena: klip przycięty od początku sceny (clips.json) do jej długości, 30 kl./s, H.264,
# lektor dopełniony ciszą do długości sceny. Napisy jako osobny plik .srt (nie wypalamy ich
# w obrazie). Domyślnie bez muzyki: muzyka tylko z licencją, która na to pozwala.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v ffmpeg >/dev/null || { echo "Potrzebny ffmpeg" >&2; exit 1; }
PYTHON=${PYTHON:-backend/.venv/bin/python}
OUT=demo/out
CLIPS=$OUT/clips/clips.json
[ -f "$CLIPS" ] || { echo "Brak $CLIPS: uruchom scripts/record_demo.sh" >&2; exit 1; }
FPS=$("$PYTHON" -c "import json;print(json.load(open('$OUT/script.json'))['fps'])")
mkdir -p "$OUT/parts"
: > "$OUT/parts/list.txt"

"$PYTHON" - "$CLIPS" <<'PY' > "$OUT/parts/plan.tsv"
import json, sys
for clip in json.load(open(sys.argv[1])):
    print(f"{clip['id']}\t{clip['file']}\t{clip['offset_ms'] / 1000:.3f}\t{clip['duration_s']}")
PY

while IFS=$'\t' read -r id file offset duration; do
  audio="$OUT/audio/$id.wav"
  part="$OUT/parts/$id.mp4"
  if [ -z "${NO_AUDIO:-}" ] && [ -f "$audio" ]; then
    ffmpeg -nostdin -loglevel error -y -ss "$offset" -t "$duration" -i "$file" -i "$audio" \
      -filter_complex "[0:v]fps=$FPS,scale=1920:1080,format=yuv420p[v];[1:a]apad,atrim=0:$duration,aresample=48000[a]" \
      -map "[v]" -map "[a]" -c:v libx264 -preset medium -crf 20 -c:a aac -b:a 160k -t "$duration" "$part"
  else
    [ -n "${NO_AUDIO:-}" ] || echo "Uwaga: brak lektora dla sceny $id ($audio), wstawiam ciszę" >&2
    ffmpeg -nostdin -loglevel error -y -ss "$offset" -t "$duration" -i "$file" \
      -f lavfi -t "$duration" -i anullsrc=r=48000:cl=stereo \
      -filter_complex "[0:v]fps=$FPS,scale=1920:1080,format=yuv420p[v]" \
      -map "[v]" -map 1:a -c:v libx264 -preset medium -crf 20 -c:a aac -b:a 160k -t "$duration" "$part"
  fi
  echo "file '$PWD/$part'" >> "$OUT/parts/list.txt"
done < "$OUT/parts/plan.tsv"

ffmpeg -loglevel error -y -f concat -safe 0 -i "$OUT/parts/list.txt" -c copy "$OUT/demo.mp4"
"$PYTHON" scripts/demo_script.py srt > "$OUT/demo.srt"
length=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$OUT/demo.mp4")
echo "Gotowe: $OUT/demo.mp4 (${length} s) i $OUT/demo.srt"
"$PYTHON" -c "import sys; sys.exit(float('$length') > 60.5)" || { echo "Film dłuższy niż 60 s" >&2; exit 1; }
