#!/usr/bin/env bash
# Uruchamia demo: stos aplikacji + celowo podatny demo-lab, a potem pełną ścieżkę
# (import inwentarza, feedy offline, skan, dopasowanie, ocena ryzyka, powiadomienia).
#
# Wymaga DEMO_MODE=true w pliku .env. Skrypt tego pliku nie zmienia: tryb demo włącza
# świadomie człowiek. Zakres skanowania to wyłącznie izolowana sieć demo-lab.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Brak pliku .env. Wykonaj: cp .env.example .env i ustaw POSTGRES_PASSWORD." >&2
  exit 1
fi
if ! grep -Eq '^DEMO_MODE=true[[:space:]]*$' .env; then
  echo "seed_demo działa tylko przy DEMO_MODE=true w pliku .env (domyślnie false)." >&2
  exit 1
fi

# Zakres: tylko demo-lab. Zgoda seed_demo na skany inwazyjne wygasa po 4 godzinach.
export SCOPE_FILE=/app/rules/scope.demo.yaml
if [ -z "${DEMO_APPROVAL_EXPIRES_AT:-}" ]; then
  DEMO_APPROVAL_EXPIRES_AT="$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -v+4H +%Y-%m-%dT%H:%M:%SZ)"
fi
export DEMO_APPROVAL_EXPIRES_AT

mkdir -p data/feeds
echo "==> Start stosu z profilem demo (zgoda seed_demo do ${DEMO_APPROVAL_EXPIRES_AT})"
docker compose --profile demo up -d --build

echo "==> Czekam 25 s, aż usługi demo-lab zaczną nasłuchiwać"
sleep 25

echo "==> seed-demo w kontenerze skanera"
docker compose exec -T worker-scans python -m app.cli seed-demo

if grep -Eq '^LLM_MODEL=[^[:space:]]+' .env; then
  echo "==> Wyjaśnienia: zlecam generowanie w tle (kolejka llm, niski priorytet)"
  docker compose exec -T worker-llm python -m app.cli explain --queue || \
    echo "Model niedostępny; interfejs pokaże wyjaśnienia z szablonu (scripts/fetch_models.sh)."
fi

echo
echo "Gotowe. Interfejs: http://localhost:8080"
echo "Uwaga: zwykłe 'docker compose up' przywraca pusty zakres skanowania."
