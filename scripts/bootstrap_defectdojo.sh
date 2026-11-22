#!/usr/bin/env bash
# Tworzy lokalny product/engagement/test i token API; zapisuje je wyłącznie w ignorowanym .env.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
result_file=$(mktemp)
trap 'rm -f "$result_file"' EXIT
code=$(cat <<'PY'
import json
from datetime import date
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from dojo.models import Product_Type, Product, Engagement, Test_Type, Test
admin = User.objects.get(username="admin")
token, _ = Token.objects.get_or_create(user=admin)
ptype, _ = Product_Type.objects.get_or_create(name="Sentinel ASI")
product, _ = Product.objects.get_or_create(name="Sentinel ASI Demo", defaults={"description": "Lokalne obserwacje Sentinel ASI", "prod_type": ptype})
engagement, _ = Engagement.objects.get_or_create(product=product, name="Sprint final", defaults={"target_start": date.today(), "target_end": date.today()})
test_type, _ = Test_Type.objects.get_or_create(name="Sentinel ASI Discovery")
test, _ = Test.objects.get_or_create(engagement=engagement, test_type=test_type, title="Discovery", defaults={"target_start": date.today(), "target_end": date.today()})
print(json.dumps({"token": token.key, "product": product.id, "engagement": engagement.id, "test": test.id}))
PY
)
docker compose -f docker-compose.yml -f docker-compose.defectdojo.yml exec -T dd-uwsgi python manage.py shell -c "$code" > "$result_file"
"$(command -v python3 || command -v python)" - "$result_file" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text().strip().splitlines()[-1])
path = Path(".env")
values = {
    "DEFECTDOJO_URL": "http://dd-nginx:8080",
    "DEFECTDOJO_API_TOKEN": str(data["token"]),
    "DEFECTDOJO_TOKEN": str(data["token"]),
    "DEFECTDOJO_PRODUCT_ID": str(data["product"]),
    "DEFECTDOJO_ENGAGEMENT_ID": str(data["engagement"]),
    "DEFECTDOJO_TEST_ID": str(data["test"]),
}
lines = path.read_text().splitlines()
lines = [line for line in lines if line.partition("=")[0] not in values]
lines.extend(f"{key}={value}" for key, value in values.items())
path.write_text("\n".join(lines) + "\n")
path.chmod(0o600)
print("Lokalny profil DefectDojo skonfigurowany")
PY
# Nowe zmienne z .env trafiają do kontenerów dopiero po ich odtworzeniu (sam restart nie wystarczy).
docker compose -f docker-compose.yml -f docker-compose.defectdojo.yml up -d --no-deps --no-build \
  api worker-core worker-scans >/dev/null
