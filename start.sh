#!/usr/bin/env bash
# Start demo jedną komendą (Linux, macOS, Git Bash): ./start.sh
# Wymaga tylko Dockera z compose. .env i hasła przygotowuje scripts/ensure_env.sh.
set -euo pipefail
# Git Bash na Windowsie zamienia argumenty i zmienne typu /opt/... na ścieżki Windows; wyłączamy to.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")"

# Docker Desktop na Windowsie: katalog z docker.exe przekazuje start.ps1 (Git Bash może go nie mieć w PATH).
if [ -n "${SENTINEL_DOCKER_DIR:-}" ] && command -v cygpath >/dev/null 2>&1; then
  PATH="$(cygpath -u "$SENTINEL_DOCKER_DIR"):$PATH"
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Nie widzę polecenia docker w PATH. Zainstaluj/uruchom Docker Desktop i spróbuj ponownie." >&2
  exit 1
fi
if ! err=$(docker info 2>&1); then
  echo "Docker nie działa. Uruchom Docker Desktop (albo usługę docker) i spróbuj ponownie." >&2
  echo "Szczegóły z 'docker info':" >&2
  printf '%s\n' "$err" | tail -n 5 >&2
  exit 1
fi
# Kopie z Windowsa mogą mieć CRLF w skryptach; bash i kontenery potrzebują LF.
git ls-files -z -- '*.sh' 2>/dev/null | xargs -0 -r sed -i 's/\r$//' 2>/dev/null || true

bash ./scripts/seed_demo.sh
