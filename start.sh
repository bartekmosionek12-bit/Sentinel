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
# Docker Desktop ma w resources/bin obok docker.exe skrypt „docker” dla WSL (#!/usr/bin/env sh).
# Git Bash wybiera go pierwszy i kończy się „required file not found”. Dlatego na Windowsie
# kładziemy przed nim własny zamiennik w .bin/, który zawsze woła prawdziwy docker.exe.
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*)
    if command -v docker.exe >/dev/null 2>&1; then
      mkdir -p .bin
      printf '#!/bin/sh\nexec docker.exe "$@"\n' > .bin/docker
      printf '#!/bin/sh\nexec docker.exe compose "$@"\n' > .bin/docker-compose
      chmod +x .bin/docker .bin/docker-compose
      PATH="$PWD/.bin:$PATH"
    fi
    ;;
esac
export PATH
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

# Stara kopia projektu w innym folderze (np. sentinel-asi) zostawia sieć z tą samą podsiecią
# demo-lab i Docker odmawia utworzenia nowej („Pool overlaps”). Zatrzymujemy tamtą kopię
# (kontenery i sieci; wolumeny z danymi zostają) i stawiamy tę.
project=$(basename "$PWD" | tr '[:upper:]' '[:lower:]')
for net in $(docker network ls -q 2>/dev/null); do
  subnets=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$net" 2>/dev/null || true)
  case " $subnets " in *" 172.30.99.0/24 "*) ;; *) continue ;; esac
  name=$(docker network inspect -f '{{.Name}}' "$net")
  [ "$name" = "${project}_demo-lab" ] && continue
  other=$(docker network inspect -f '{{index .Labels "com.docker.compose.project"}}' "$net" 2>/dev/null || true)
  if [ -z "$other" ] || [ "$other" = "<no value>" ]; then
    echo "Sieć $name zajmuje podsieć 172.30.99.0/24 demo-lab. Usuń ją: docker network rm $name" >&2
    exit 1
  fi
  echo "==> Zatrzymuję starą kopię ($other), bo zajmuje podsieć demo-lab (dane w wolumenach zostają)"
  docker ps -aq --filter "label=com.docker.compose.project=$other" | xargs -r docker rm -f >/dev/null
  docker network ls -q --filter "label=com.docker.compose.project=$other" | xargs -r docker network rm >/dev/null
done

# ./start.sh --bez-demo [--czysta-baza]: własne cele (np. lab mentorów) zamiast demo-lab.
if [ "${1:-}" = "--bez-demo" ]; then
  shift
  exec bash ./scripts/start_live.sh "$@"
fi
bash ./scripts/seed_demo.sh
bash ./scripts/show_accounts.sh
