#!/usr/bin/env bash
# Film demo 90 s jedną komendą: ./scripts/make_demo.sh  →  demo/out/demo.mp4 (napisy wypalone)
#
# Kolejno:
#   1. stos aplikacji + demo-lab + DefectDojo (docker compose, profile demo i defectdojo),
#   2. konta demo, zakres demo-lab i token DefectDojo (tylko przy pierwszym uruchomieniu),
#   3. stan do nagrania przez API: trzy przebiegi discovery ze zmianą między nimi,
#   4. nagranie 7 scen Playwrightem (1920×1080, 30 kl./s) na prawdziwym API,
#   5. lektor (Piper, pl_PL-darkman-medium) z kontrolą, że mieści się w scenach,
#   6. montaż ffmpeg z wypalonymi napisami.
# Kroki 4–6 działają w kontenerze narzędzi (docker-compose.demo-video.yml), więc na komputerze
# potrzebny jest tylko Docker z compose oraz bash, curl i python3.
# Bez ręcznych ustawień (.env przygotowuje scripts/ensure_env.sh). Nic nie trafia do Gita (demo/out).
#   SKIP_STAGE=1 ./scripts/make_demo.sh   # nagraj ponownie na istniejących przebiegach
#   ONLY=skan ./scripts/make_demo.sh      # tylko jedna scena (poprawka), bez montażu
set -euo pipefail
# Git Bash na Windowsie zamienia argumenty i zmienne typu /opt/... na ścieżki Windows; wyłączamy to.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' MSYS2_ENV_CONV_EXCL='*'
cd "$(dirname "$0")/.."

./scripts/ensure_env.sh   # .env, DEMO_MODE=true i brakujące hasła bez ręcznych ustawień

export COMPOSE_FILE=docker-compose.yml:docker-compose.defectdojo.yml:docker-compose.demo-video.yml
export COMPOSE_PROFILES=demo,defectdojo
BASE=http://localhost:8080
OUT=demo/out
mkdir -p "$OUT"

echo "==> 1/6 Stos aplikacji, demo-lab i DefectDojo"
if [ ! -f data/demo-credentials.env ]; then
  ./scripts/seed_demo.sh   # pierwszy raz: build, zakres demo-lab, konta demo z TOTP
else
  SCOPE_FILE=/app/rules/scope.demo.yaml docker compose up -d --build
fi

echo "==> 2/6 Token DefectDojo"
if ! grep -Eq '^DEFECTDOJO_TOKEN=.+' .env; then
  ./scripts/defectdojo_token.sh
  SCOPE_FILE=/app/rules/scope.demo.yaml docker compose up -d api worker-core worker-scans
fi
for _ in $(seq 1 60); do
  curl -fs -o /dev/null "$BASE/api/health" && break
  sleep 3
done

echo "==> 3/6 Stan do nagrania (trzy przebiegi discovery przez API)"
if [ -z "${SKIP_STAGE:-}" ] || [ ! -f "$OUT/stage.json" ]; then
  PY=$(command -v python3 >/dev/null && python3 -c "" 2>/dev/null && echo python3 || echo python)
  "$PY" scripts/demo_stage.py "$BASE" "$OUT/stage.json"
fi
docker compose stop lab-poisoned >/dev/null 2>&1 || true
trap 'docker compose start lab-poisoned >/dev/null 2>&1 || true' EXIT

echo "==> 4/6 Nagranie scen (Playwright w kontenerze narzędzi)"
./scripts/record_demo.sh
[ -n "${ONLY:-}" ] && { echo "Nagrano scenę $ONLY (demo/out/clips)."; exit 0; }

echo "==> 5/6 Lektor i 6/6 montaż z napisami"
COMPOSE_PROFILES=demo-video docker compose run --rm --no-deps demo-tools bash -c '
  set -e
  PYTHON=python3 ./scripts/demo_tts.sh
  PYTHON=python3 ./scripts/assemble_demo.sh'
echo "Film: $OUT/demo.mp4"
