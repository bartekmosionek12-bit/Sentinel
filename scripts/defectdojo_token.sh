#!/usr/bin/env bash
# Pobiera token API z lokalnego DefectDojo (login z .env) i zapisuje go w .env jako
# DEFECTDOJO_TOKEN. Token nie jest wypisywany na ekran. Potem: docker compose restart api worker-core
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
URL=${DEFECTDOJO_PUBLIC_URL:-http://localhost:8081}
for _ in $(seq 1 60); do
  curl -fs -o /dev/null "$URL/login" && break
  echo "Czekam na DefectDojo ($URL)..."; sleep 5
done
TOKEN=$(curl -fs -X POST "$URL/api/v2/api-token-auth/" -H "Content-Type: application/json" \
  --data "$(python3 -c 'import json,os;print(json.dumps({"username":os.environ.get("DD_ADMIN_USER","admin"),"password":os.environ["DD_ADMIN_PASSWORD"]}))')" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
if grep -q '^DEFECTDOJO_TOKEN=' .env; then
  sed -i "s|^DEFECTDOJO_TOKEN=.*|DEFECTDOJO_TOKEN=$TOKEN|" .env
else
  echo "DEFECTDOJO_TOKEN=$TOKEN" >> .env
fi
grep -q '^DEFECTDOJO_URL=' .env || echo "DEFECTDOJO_URL=http://dd-nginx:8080" >> .env
echo "Zapisano DEFECTDOJO_TOKEN w .env. Zrestartuj api: docker compose restart api"
