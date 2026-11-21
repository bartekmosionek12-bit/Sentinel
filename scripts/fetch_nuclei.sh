#!/usr/bin/env bash
# Pobiera nuclei i WYŁĄCZNIE szablony wykrywające z rules/nuclei.yaml do data/nuclei/ (poza
# Gitem). Kontener mcp-scanner montuje je tylko do odczytu i nie ma dostępu do internetu
# (nuclei uruchamiany z -disable-update-check).
#
# Wersje są przypięte, a pliki sprawdzane sumą SHA-256. Zmiana wersji = nowa suma w tym pliku.
set -euo pipefail
cd "$(dirname "$0")/.."

NUCLEI_VERSION=3.11.1
NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6  # linux_amd64
TEMPLATES_TAG=v10.5.1
# ścieżka w repozytorium nuclei-templates | SHA-256
TEMPLATES=(
  "http/technologies/apache/apache-detect.yaml|2b15aaf0e02234242b44a86684fa38aa7bb68cb01d88b41de5f78cc971a8cdd3"
  "http/technologies/nginx/nginx-version.yaml|aa410fb8361f2109ac247b16419040cc2cce1e3d9c76f0a51593806e7c1b7cd7"
)

DEST=data/nuclei
mkdir -p "$DEST/bin" "$DEST/templates"

check() { echo "$2  $1" | sha256sum -c --status; }

if [ "$(uname -m)" != "x86_64" ]; then
  echo "Skrypt przypina binarkę linux_amd64; na innej architekturze podmień NUCLEI_SHA256." >&2
  exit 1
fi

if [ -x "$DEST/bin/nuclei" ] && [ -f "$DEST/bin/.version" ] && [ "$(cat "$DEST/bin/.version")" = "$NUCLEI_VERSION" ]; then
  echo "==> nuclei $NUCLEI_VERSION: już pobrany"
else
  zip="$DEST/nuclei.zip"
  curl -fsSL -o "$zip" \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
  check "$zip" "$NUCLEI_SHA256" || { echo "Zła suma SHA-256 nuclei" >&2; rm -f "$zip"; exit 1; }
  python3 -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract('nuclei', sys.argv[2])" "$zip" "$DEST/bin"
  chmod 0755 "$DEST/bin/nuclei"
  echo "$NUCLEI_VERSION" > "$DEST/bin/.version"
  rm -f "$zip"
  echo "==> nuclei $NUCLEI_VERSION pobrany"
fi

for entry in "${TEMPLATES[@]}"; do
  path=${entry%%|*}
  sha=${entry##*|}
  file="$DEST/templates/$(basename "$path")"
  if [ -f "$file" ] && check "$file" "$sha"; then
    continue
  fi
  curl -fsSL -o "$file" \
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/${TEMPLATES_TAG}/${path}"
  check "$file" "$sha" || { echo "Zła suma SHA-256 szablonu $path" >&2; rm -f "$file"; exit 1; }
done
echo "==> szablony wykrywające: ${#TEMPLATES[@]} (nuclei-templates $TEMPLATES_TAG)"
