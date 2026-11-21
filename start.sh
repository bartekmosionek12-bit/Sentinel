#!/usr/bin/env bash
# Start demo jedną komendą (Linux, macOS, Git Bash): ./start.sh
# Wymaga tylko Dockera z compose. .env i hasła przygotowuje scripts/ensure_env.sh.
set -euo pipefail
# Git Bash na Windowsie zamienia argumenty i zmienne typu /opt/... na ścieżki Windows; wyłączamy to.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' MSYS2_ENV_CONV_EXCL='*'
cd "$(dirname "$0")"

if ! docker info >/dev/null 2>&1; then
  echo "Docker nie działa. Uruchom Docker Desktop (albo usługę docker) i spróbuj ponownie." >&2
  exit 1
fi
# Kopie z Windowsa mogą mieć CRLF w skryptach; bash i kontenery potrzebują LF.
git ls-files -z -- '*.sh' 2>/dev/null | xargs -0 -r sed -i 's/\r$//' 2>/dev/null || true

./scripts/seed_demo.sh
