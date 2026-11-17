#!/usr/bin/env bash
# Pobiera snapshoty feedów (NVD, CISA KEV, EPSS) do data/feeds/, poza Gitem.
# Wymaga internetu. Uruchom PRZED prezentacją bez sieci, po zaimportowaniu inwentarza:
# z NVD pobierane są CVE dla produktów z inwentarza oraz zmiany z ostatnich dni.
# Klucz NVD_API_KEY w .env jest opcjonalny (bez niego pobieranie trwa dłużej).
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p data/feeds
docker compose run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/data/feeds:/out" \
  worker-feeds python -m app.cli fetch-feeds --out /out

echo "Snapshoty zapisane w data/feeds/. Wczytanie: docker compose exec worker-feeds python -m app.cli sync-feeds"
