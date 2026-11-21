#!/usr/bin/env bash
# Moduł 22: nagranie scen filmu demo (1920×1080) według demo/script.yaml.
#
#   python3 scripts/demo_stage.py http://localhost:8080   # stan: test agenta, lease SSH
#   ./scripts/record_demo.sh     # klipy w demo/out/clips, potem ./scripts/assemble_demo.sh
#   ONLY=raport ./scripts/record_demo.sh   # jedna scena (poprawka)
#
# Tylko DEMO_MODE=true. Tryb nagrywania (?demo=record) i tak działa wyłącznie przy DEMO_MODE.
# Scena „zero-day” wstrzykuje wpis KEV (scripts/inject_kev.sh), więc całość nagrywamy na
# świeżo przygotowanym stanie. Wynik jest poza Gitem (demo/out w .gitignore).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! grep -Eq '^DEMO_MODE=true[[:space:]]*$' .env 2>/dev/null; then
  echo "Nagrywanie demo działa tylko przy DEMO_MODE=true w pliku .env." >&2
  exit 1
fi
[ -f data/demo-credentials.env ] || { echo "Brak data/demo-credentials.env: uruchom scripts/seed_demo.sh" >&2; exit 1; }
PYTHON=${PYTHON:-backend/.venv/bin/python}
mkdir -p demo/out/clips
"$PYTHON" scripts/demo_script.py check
"$PYTHON" scripts/demo_script.py json > demo/out/script.json

export BASE_URL=${BASE_URL:-http://localhost:8080}
export SCRIPT_JSON="$PWD/demo/out/script.json"
export OUT_DIR="$PWD/demo/out/clips"
export CREDENTIALS="$PWD/data/demo-credentials.env"
cd frontend
node scripts/record-demo.mjs
