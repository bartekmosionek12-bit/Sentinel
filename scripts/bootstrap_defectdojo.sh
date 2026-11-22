#!/usr/bin/env bash
# Tworzy lokalny product/engagement/test i token API; zapisuje je wyłącznie w ignorowanym .env.
# Bez Pythona na hoście i bez plików tymczasowych: na Windowsie (Git Bash + Python z Windowsa)
# ścieżka /tmp z mktemp nie istnieje dla Pythona, stąd wcześniejszy FileNotFoundError.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
code=$(cat <<'PY'
from django.utils import timezone
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from dojo.models import Product_Type, Product, Engagement, Test_Type, Test
now = timezone.now()
admin = User.objects.get(username="admin")
token, _ = Token.objects.get_or_create(user=admin)
ptype, _ = Product_Type.objects.get_or_create(name="Sentinel ASI")
product, _ = Product.objects.get_or_create(name="Sentinel ASI Demo", defaults={"description": "Lokalne obserwacje Sentinel ASI", "prod_type": ptype})
engagement, _ = Engagement.objects.get_or_create(product=product, name="Sprint final", defaults={"target_start": now.date(), "target_end": now.date()})
test_type, _ = Test_Type.objects.get_or_create(name="Sentinel ASI Discovery")
test, _ = Test.objects.get_or_create(engagement=engagement, test_type=test_type, title="Discovery", defaults={"target_start": now, "target_end": now})
print("SENTINEL_DD_VALUES", token.key, product.id, engagement.id, test.id)
PY
)
output=$(docker compose -f docker-compose.yml -f docker-compose.defectdojo.yml exec -T dd-uwsgi \
  python manage.py shell -c "$code" | tr -d '\r')
read -r _ token product engagement test < <(printf '%s\n' "$output" | grep '^SENTINEL_DD_VALUES ' | tail -n 1) || true
if [ -z "${token:-}" ] || [ -z "${test:-}" ]; then
  echo "Nie udało się odczytać tokenu DefectDojo. Wyjście:" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

keys="DEFECTDOJO_URL DEFECTDOJO_API_TOKEN DEFECTDOJO_TOKEN DEFECTDOJO_PRODUCT_ID DEFECTDOJO_ENGAGEMENT_ID DEFECTDOJO_TEST_ID"
touch .env
new_env=$(awk -v keys="$keys" 'BEGIN { n = split(keys, k, " "); for (i = 1; i <= n; i++) drop[k[i]] = 1 }
  { sub(/\r$/, ""); split($0, kv, "="); if (!(kv[1] in drop)) print }' .env)
{
  [ -n "$new_env" ] && printf '%s\n' "$new_env"
  printf 'DEFECTDOJO_URL=http://dd-nginx:8080\n'
  printf 'DEFECTDOJO_API_TOKEN=%s\nDEFECTDOJO_TOKEN=%s\n' "$token" "$token"
  printf 'DEFECTDOJO_PRODUCT_ID=%s\nDEFECTDOJO_ENGAGEMENT_ID=%s\nDEFECTDOJO_TEST_ID=%s\n' "$product" "$engagement" "$test"
} > .env.tmp
mv .env.tmp .env
chmod 600 .env 2>/dev/null || true
echo "Lokalny profil DefectDojo skonfigurowany"

# Nowe zmienne z .env trafiają do kontenerów dopiero po ich odtworzeniu (sam restart nie wystarczy).
# DD_NO_RESTART=1: wywołanie ze start.sh przed startem aplikacji, więc nie ma czego odtwarzać.
if [ -z "${DD_NO_RESTART:-}" ]; then
  docker compose -f docker-compose.yml -f docker-compose.defectdojo.yml up -d --no-deps --no-build \
    api worker-core worker-scans >/dev/null
fi
