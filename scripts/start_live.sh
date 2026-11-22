#!/usr/bin/env bash
# Tryb bez demo: ./start.sh --bez-demo [--czysta-baza]
#
#   * DEMO_MODE=false: bez banera „Tryb demo”, bez seed-demo i bez sieci demo-lab,
#   * zakres skanowania: rules/scope.mentor-lab.yaml (komputer z labem mentorów jako
#     host.docker.internal); własny plik: SCOPE_FILE=/app/rules/<plik>.yaml ./start.sh --bez-demo,
#   * lokalne DefectDojo i te same cztery konta z TOTP co w demo (data/demo-credentials.env),
#   * --czysta-baza: usuwa wolumeny tego projektu (baza, Keycloak, DefectDojo), więc na
#     pulpicie nie ma danych z wcześniejszego demo. Nieodwracalne, dlatego tylko na życzenie.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."

export COMPOSE_PATH_SEPARATOR=:
export COMPOSE_FILE=docker-compose.yml:docker-compose.defectdojo.yml
export SCOPE_FILE=${SCOPE_FILE:-/app/rules/scope.mentor-lab.yaml}

if [ "${1:-}" = "--czysta-baza" ]; then
  echo "==> Usuwam kontenery i wolumeny tego projektu (dane z demo znikną)"
  docker compose --profile demo --profile defectdojo down -v --remove-orphans
fi

SENTINEL_DEMO=0 bash ./scripts/ensure_env.sh

profiles=()
echo "==> Lokalne DefectDojo (pierwsze uruchomienie: kilka minut na migracje bazy)"
if DD_NO_RESTART=1 bash ./scripts/defectdojo_local.sh; then
  profiles+=(--profile defectdojo)
else
  echo "DefectDojo nie wystartowało; aplikacja działa dalej, eksport przez „Pobierz nmap XML”." >&2
fi

echo "==> Start aplikacji bez demo (zakres: ${SCOPE_FILE})"
# Kontenery demo-lab z wcześniejszego uruchomienia demo nie są tu potrzebne.
docker compose --profile demo rm -sf mailpit lab-web lab-proxy lab-legacy lab-shop lab-cache \
  lab-poisoned lab-ssh >/dev/null 2>&1 || true
docker compose "${profiles[@]}" up -d --build

echo "==> Konta w Keycloaku (admin, editor, modifier, viewer; każde z TOTP)"
SENTINEL_ACCOUNTS=1 bash ./scripts/demo_users.sh

bash ./scripts/wait_ready.sh
echo
echo "Gotowe (tryb bez demo)."
echo "  Konsola zespołu IT:  http://localhost:8080/admin/"
echo "  DefectDojo:          http://localhost:8081"
echo "  Hasła i TOTP kont:   data/demo-credentials.env"
echo "  Discovery → Cele: host.docker.internal (lab mentorów musi działać: ./quickstart.sh up)"
echo "  Powrót do demo: ./start.sh"
