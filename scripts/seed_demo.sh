#!/usr/bin/env bash
# Uruchamia demo: stos aplikacji + celowo podatny demo-lab, a potem pełną ścieżkę
# (import inwentarza, feedy offline, skan, dopasowanie, ocena ryzyka, powiadomienia).
#
# Bez ręcznych ustawień: scripts/ensure_env.sh tworzy .env, włącza DEMO_MODE i generuje
# brakujące hasła. Zakres skanowania to wyłącznie izolowana sieć demo-lab.
set -euo pipefail
# Git Bash na Windowsie zamienia argumenty i zmienne typu /opt/... na ścieżki Windows; wyłączamy to.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."

bash ./scripts/ensure_env.sh

# Zakres: tylko demo-lab. Zgoda seed_demo na skany inwazyjne wygasa po 4 godzinach.
export SCOPE_FILE=/app/rules/scope.demo.yaml
if [ -z "${DEMO_APPROVAL_EXPIRES_AT:-}" ]; then
  DEMO_APPROVAL_EXPIRES_AT="$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -v+4H +%Y-%m-%dT%H:%M:%SZ)"
fi
export DEMO_APPROVAL_EXPIRES_AT

mkdir -p data/feeds
echo "==> nuclei i szablony detekcji (przypięte wersje i sumy SHA-256)"
bash ./scripts/fetch_nuclei.sh || \
  echo "nuclei niedostępny: narzędzie verify_cve agenta zwróci błąd, reszta demo działa."
echo "==> Start stosu z profilem demo (zgoda seed_demo do ${DEMO_APPROVAL_EXPIRES_AT})"
docker compose --profile demo up -d --build

echo "==> Czekam 25 s, aż usługi demo-lab zaczną nasłuchiwać"
sleep 25

echo "==> seed-demo w kontenerze skanera"
docker compose exec -T worker-scans python -m app.cli seed-demo

echo "==> Agent: zdolności dla demo-lab (L0-L2); działają po zaliczonym teście agenta"
docker compose exec -T worker-agent python -m app.cli agent-bootstrap

echo "==> Konta demo w Keycloaku (admin, editor, modifier, viewer; każde z TOTP)"
bash ./scripts/demo_users.sh

# Domyślny model to Qwen3 4B (LLM_MODEL=qwen3-4b-q4km w .env.example, wybór: eval/RESULTS.md).
LLM_MODEL_NAME=$(grep -E '^LLM_MODEL=' .env | tail -n1 | cut -d= -f2- | tr -d '"[:space:]' || true)
if [ -n "$LLM_MODEL_NAME" ]; then
  echo "==> Wyjaśnienia modelem ${LLM_MODEL_NAME}: generowanie w tle (kolejka llm, niski priorytet)"
  docker compose exec -T worker-llm python -m app.cli explain --queue || \
    echo "Model ${LLM_MODEL_NAME} niedostępny; interfejs pokaże wyjaśnienia z szablonu." \
      "Pobierz go: ./scripts/fetch_models.sh"
else
  echo "==> LLM_MODEL jest pusty: wyjaśnienia z szablonu (domyślnie: LLM_MODEL=qwen3-4b-q4km)"
fi

PUBLIC_URL_VALUE=$(grep -E '^PUBLIC_URL=' .env | tail -n1 | cut -d= -f2- | tr -d '"[:space:]' || true)
PUBLIC_URL_VALUE=${PUBLIC_URL_VALUE:-http://localhost:8080}
echo "==> Sprawdzam, czy konsola odpowiada przez nginx (${PUBLIC_URL_VALUE}/api/health)"
ok=""
for _ in $(seq 1 60); do
  code=$(docker compose exec -T frontend wget -q -O /dev/null -S http://127.0.0.1:8080/api/health 2>&1 \
    | awk '/HTTP\//{print $2}' | tail -n1 || true)
  [ "$code" = "200" ] && { ok=1; break; }
  sleep 3
done
if [ -z "$ok" ]; then
  echo "Konsola nie odpowiada (ostatni kod: ${code:-brak}). Stan usług i ostatnie logi api:" >&2
  docker compose ps api frontend keycloak >&2 || true
  docker compose logs --tail 40 api >&2 || true
  exit 1
fi
echo
echo "Gotowe."
echo "  Konsola zespołu IT:   ${PUBLIC_URL_VALUE}/admin/"
echo "  Hasła i sekret TOTP kont demo: data/demo-credentials.env"
echo "Uwaga: zwykłe 'docker compose up' przywraca pusty zakres skanowania."
