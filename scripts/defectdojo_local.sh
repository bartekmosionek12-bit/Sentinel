#!/usr/bin/env bash
# Lokalne DefectDojo (blok E): pobiera obrazy, uruchamia profil `defectdojo`, zakłada
# product/engagement/test i token API, zapisuje je w .env i odtwarza api oraz workery.
#
#   ./scripts/defectdojo_local.sh
#
# start.sh woła go sam przy każdym uruchomieniu (z DD_NO_RESTART=1, przed startem aplikacji),
# więc DefectDojo wstaje razem z resztą. Ponowne uruchomienie jest bezpieczne: product,
# engagement, test i token są te same (get_or_create).
#
# Interfejs DefectDojo: http://localhost:8081 (DD_ADMIN_USER / DD_ADMIN_PASSWORD z .env).
# Nie ma atrapy: jeśli obrazów nie da się pobrać, DefectDojo po prostu nie działa, a w
# aplikacji zostaje eksport nmap XML (Skany → „Pobierz nmap XML”).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."
bash ./scripts/ensure_env.sh
compose=(docker compose -f docker-compose.yml -f docker-compose.defectdojo.yml --profile defectdojo)

echo "==> Start DefectDojo (brakujące obrazy z Docker Hub; pierwsze uruchomienie trwa kilka minut)"
if ! log=$("${compose[@]}" up -d --pull missing dd-nginx dd-celeryworker 2>&1); then
  echo "$log" | tail -5 >&2
  if grep -qiE "429|toomanyrequests|rate limit" <<<"$log"; then
    echo "Docker Hub odrzucił pobieranie (limit anonimowych pobrań, HTTP 429)." >&2
    echo "Zaloguj się kontem Docker Hub (docker login) albo spróbuj za kilka godzin." >&2
  fi
  echo "DefectDojo nie zostało uruchomione. Eksport działa przez Skany → „Pobierz nmap XML”." >&2
  exit 1
fi
for _ in $(seq 1 90); do
  if "${compose[@]}" exec -T dd-uwsgi python manage.py check >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 5
done
if [ -z "${ready:-}" ]; then
  echo "DefectDojo nie wstało w 7,5 min. Logi: docker compose -f docker-compose.yml -f docker-compose.defectdojo.yml logs dd-initializer dd-uwsgi" >&2
  exit 1
fi

echo "==> Token API i product/engagement/test w .env"
bash ./scripts/bootstrap_defectdojo.sh
echo "DefectDojo działa: http://localhost:8081 (login: DD_ADMIN_USER / DD_ADMIN_PASSWORD z .env)."
