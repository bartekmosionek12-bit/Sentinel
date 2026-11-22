#!/usr/bin/env bash
# Czeka, aż konsola odpowiada przez nginx (/api/health = 200). Jeśli nie, pokazuje stan usług
# i ostatnie logi api, żeby od razu było widać, czemu konsola zwraca 502.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."
echo "==> Sprawdzam, czy konsola odpowiada przez nginx (/api/health)"
code=""
for _ in $(seq 1 60); do
  code=$(docker compose exec -T frontend wget -q -O /dev/null -S http://127.0.0.1:8080/api/health 2>&1 \
    | awk '/HTTP\//{print $2}' | tail -n1 || true)
  [ "$code" = "200" ] && exit 0
  sleep 3
done
echo "Konsola nie odpowiada (ostatni kod: ${code:-brak}). Stan usług i ostatnie logi api:" >&2
docker compose ps api frontend keycloak >&2 || true
docker compose logs --tail 40 api >&2 || true
exit 1
