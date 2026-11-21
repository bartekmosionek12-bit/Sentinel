#!/usr/bin/env bash
# W kontenerze narzędzi `localhost:8080` i `localhost:8081` prowadzą do konsoli i DefectDojo,
# tak jak w przeglądarce na komputerze (adresy w tokenach Keycloaka muszą się zgadzać).
set -euo pipefail
socat TCP-LISTEN:8080,fork,reuseaddr TCP:frontend:8080 &
socat TCP-LISTEN:8081,fork,reuseaddr TCP:dd-nginx:8080 &
sleep 0.5
exec "$@"
