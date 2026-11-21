#!/usr/bin/env bash
# Izolacja sieci na żywo (CI, demo-lab): próba połączenia TCP z hostem demo-lab z każdego
# kontenera. Do celów mają dojść tylko skanery (worker-scans: pipeline, mcp-scanner: agent),
# a z żadnego innego kontenera, łącznie z workerem agenta, nie może być drogi.
# Kod wyjścia 1 przy pierwszej niezgodności. Statycznie to samo: backend/tests/test_network_isolation.py.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_HOST=172.30.99.10
TARGET_PORT=80
PROBE="import socket,sys
s=socket.socket(); s.settimeout(3)
try:
    s.connect(('${TARGET_HOST}', ${TARGET_PORT})); print('open')
except OSError:
    print('closed')"

failed=0
check() {
  local service=$1 expected=$2 got
  got=$(docker compose exec -T "$service" python -c "$PROBE" 2>/dev/null | tail -n1 || true)
  if [ "$got" = "$expected" ]; then
    echo "OK   $service → ${TARGET_HOST}:${TARGET_PORT}: $got"
  else
    echo "BŁĄD $service → ${TARGET_HOST}:${TARGET_PORT}: oczekiwano $expected, jest ${got:-brak odpowiedzi}"
    failed=1
  fi
}

# Kontrola, że sonda w ogóle umie wykryć drogę do celu.
check worker-scans open
check mcp-scanner open
for service in api worker-agent worker-llm worker-harness worker-core worker-feeds; do
  check "$service" closed
done
exit "$failed"
