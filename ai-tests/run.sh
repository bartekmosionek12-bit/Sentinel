#!/usr/bin/env bash
# Uruchamia zestaw promptfoo w trybie prywatnym: bez telemetrii, zdalnej generacji, sprawdzania
# aktualizacji i udostępniania wyników. Dane testowe są fikcyjne, ale i tak nie wychodzą z maszyny.
#
#   ./run.sh mock    posłuszna atrapa, wszystkie przypadki (każdy PR, kilka sekund)
#   ./run.sh qwen    prawdziwy model, przypadki z `qwen: true` (każdy PR, z modelem w cache)
#   ./run.sh full    prawdziwy model, wszystkie przypadki (nocą i ręcznie)
set -euo pipefail
cd "$(dirname "$0")"
suite=${1:-mock}
case "$suite" in mock | qwen | full) ;; *) echo "Nieznany zestaw: $suite" >&2; exit 2 ;; esac

export PROMPTFOO_DISABLE_TELEMETRY=1
export PROMPTFOO_DISABLE_REMOTE_GENERATION=true
export PROMPTFOO_DISABLE_UPDATE=1
export PROMPTFOO_DISABLE_SHARING=1
export PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true
export PROMPTFOO_SELF_HOSTED=1
export PROMPTFOO_CONFIG_DIR="${PROMPTFOO_CONFIG_DIR:-$PWD/.promptfoo}"
export REQUEST_TIMEOUT_MS="${REQUEST_TIMEOUT_MS:-900000}"
export PROMPTFOO_PYTHON="${PROMPTFOO_PYTHON:-$PWD/../backend/.venv/bin/python}"
export PYTHONPATH="$PWD/../backend${PYTHONPATH:+:$PYTHONPATH}"

mkdir -p results
exec npx --no-install promptfoo eval -c "promptfooconfig.$suite.yaml" --no-cache --no-share \
  -j 1 -o "results/$suite.json" -o "results/$suite.html"
