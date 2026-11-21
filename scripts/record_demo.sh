#!/usr/bin/env bash
# Moduł 22: nagranie scen filmu demo (1920×1080, 30 kl./s) według demo/script.yaml.
# Playwright działa w kontenerze narzędzi (docker-compose.demo-video.yml) na prawdziwym API;
# logowanie przez Keycloak (hasło + TOTP) i formularz DefectDojo, bez obejść.
#
#   ./scripts/record_demo.sh             # wszystkie sceny → demo/out/clips
#   ONLY=skan ./scripts/record_demo.sh   # jedna scena (poprawka)
#
# Zwykle wywołuje go ./scripts/make_demo.sh (przygotowuje stan i potem montuje film).
set -euo pipefail
cd "$(dirname "$0")/.."
if ! grep -Eq '^DEMO_MODE=true[[:space:]]*$' .env 2>/dev/null; then
  echo "Nagrywanie demo działa tylko przy DEMO_MODE=true w pliku .env." >&2
  exit 1
fi
[ -f data/demo-credentials.env ] || { echo "Brak data/demo-credentials.env: uruchom scripts/make_demo.sh" >&2; exit 1; }
[ -f demo/out/stage.json ] || { echo "Brak demo/out/stage.json: uruchom scripts/make_demo.sh" >&2; exit 1; }
export COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.yml:docker-compose.defectdojo.yml:docker-compose.demo-video.yml}
DD_ADMIN_PASSWORD=$(grep -E '^DD_ADMIN_PASSWORD=' .env | tail -n1 | cut -d= -f2-)
DD_ADMIN_USER=$(grep -E '^DD_ADMIN_USER=' .env | tail -n1 | cut -d= -f2-)
mkdir -p demo/out/clips
COMPOSE_PROFILES=demo,defectdojo,demo-video docker compose run --rm --build --no-deps \
  -e ONLY="${ONLY:-}" -e DD_PASSWORD="$DD_ADMIN_PASSWORD" -e DD_USER="${DD_ADMIN_USER:-admin}" \
  demo-tools bash -c '
    set -e
    python3 scripts/demo_script.py check
    python3 scripts/demo_script.py json > demo/out/script.json
    cd frontend
    [ -d node_modules/@playwright/test ] || npm ci --no-audit --no-fund
    BASE_URL=http://localhost:8080 DD_URL=http://localhost:8081 \
      SCRIPT_JSON=/work/demo/out/script.json STAGE_JSON=/work/demo/out/stage.json \
      OUT_DIR=/work/demo/out/clips CREDENTIALS=/work/data/demo-credentials.env \
      node scripts/record-demo.mjs'
