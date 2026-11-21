#!/usr/bin/env bash
# Test na żywo na laboratorium od mentorów (lab.zip) z poziomu aplikacji.
#
#   ./scripts/mentor_lab.sh        # przełącza zakres skanera na komputer z labem
#   ./scripts/mentor_lab.sh off    # wraca do zakresu demo-lab
#
# Lab mentorów publikuje porty na localhost komputera. Skaner (worker-scans) widzi komputer
# jako host.docker.internal, a zakres pozwala tylko na ten adres i demo-lab
# (rules/scope.mentor-lab.yaml). Każdy skan nadal przechodzi przez scope_guard.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."

if [ "${1:-on}" = "off" ]; then
  echo "==> Powrót do zakresu demo-lab"
  SCOPE_FILE=/app/rules/scope.demo.yaml docker compose --profile demo up -d --no-deps api worker-scans worker-core
  exit 0
fi

bash ./scripts/ensure_env.sh
echo "==> Zakres skanera: komputer z labem mentorów (host.docker.internal) + demo-lab"
SCOPE_FILE=/app/rules/scope.mentor-lab.yaml docker compose --profile demo up -d --no-deps api worker-scans worker-core

address=""
for _ in $(seq 1 20); do
  address=$(docker compose exec -T worker-scans getent ahostsv4 host.docker.internal 2>/dev/null \
    | awk 'NR==1 {print $1}' || true)
  [ -n "$address" ] && break
  sleep 2
done
if [ -z "$address" ]; then
  echo "Skaner nie widzi host.docker.internal. Sprawdź, czy worker-scans działa: docker compose ps" >&2
  exit 1
fi
case "$address" in
  192.168.65.254 | 172.17.0.1) ;;
  *)
    echo "host.docker.internal to u Ciebie $address, a tego adresu nie ma w zakresie." >&2
    echo "Dopisz '- $address/32' w rules/scope.mentor-lab.yaml (allow.cidrs), przebuduj:" >&2
    echo "  docker compose build worker-scans api && ./scripts/mentor_lab.sh" >&2
    exit 1
    ;;
esac

cat <<EOF

Gotowe. Skaner widzi komputer jako host.docker.internal ($address).

1. Uruchom lab mentorów w osobnym terminalu, np.:  ./quickstart.sh up
2. Konsola http://localhost:8080/admin/ → Discovery → Cele: host.docker.internal → Uruchom skan
3. ./quickstart.sh change → drugi skan; ./quickstart.sh up → trzeci skan
4. Discovery → Porównanie i stany: port 8787 znika i wraca

Po teście: ./scripts/mentor_lab.sh off
EOF
