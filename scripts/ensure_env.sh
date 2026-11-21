#!/usr/bin/env bash
# Przygotowuje .env tak, żeby demo ruszyło bez ręcznych ustawień.
#
#   * brak .env -> kopia .env.example,
#   * DEMO_MODE=true (ten skrypt wołają tylko skrypty demo: seed_demo.sh, make_demo.sh),
#   * puste hasła i sekrety oraz wartości „change-me…” -> losowe (tylko w .env, poza Gitem).
#
# Wartości „change-me…” zmieniamy tylko wtedy, gdy baza jeszcze nie istnieje (brak wolumenu
# db-data), bo inaczej nowe hasło nie pasowałoby do już zainicjowanej bazy.
# Bez zależności: wystarczy bash (także Git Bash na Windowsie).
set -euo pipefail
cd "$(dirname "$0")/.."

SECRETS=(
  POSTGRES_PASSWORD APP_DB_PASSWORD KEYCLOAK_DB_PASSWORD HARNESS_DB_PASSWORD
  KEYCLOAK_ADMIN_PASSWORD AGENT_CLIENT_SECRET KILLSWITCH_CLIENT_SECRET
  DD_ADMIN_PASSWORD DD_DATABASE_PASSWORD DD_SECRET_KEY DD_CREDENTIAL_AES_256_KEY
)

random_hex() { od -An -tx1 -N24 /dev/urandom | tr -d ' \n'; }

set_value() {  # set_value NAZWA WARTOŚĆ: podmienia linię albo dopisuje ją na końcu
  if grep -Eq "^$1=" .env; then
    sed -i "s|^$1=.*|$1=$2|" .env
  else
    printf '\n%s=%s\n' "$1" "$2" >> .env
  fi
}

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Utworzyłem .env z .env.example."
fi
# Plik edytowany na Windowsie może mieć końce linii CRLF; bash i docker compose chcą LF.
sed -i 's/\r$//' .env

if ! grep -Eq '^DEMO_MODE=true[[:space:]]*$' .env; then
  set_value DEMO_MODE true
  echo "Ustawiłem DEMO_MODE=true w .env."
fi

project=$(basename "$PWD" | tr '[:upper:]' '[:lower:]')
db_exists=false
if docker volume inspect "${project}_db-data" >/dev/null 2>&1; then
  db_exists=true
fi

generated=0
for name in "${SECRETS[@]}"; do
  current=$(grep -E "^${name}=" .env | tail -n1 | cut -d= -f2- || true)
  if [ -z "$current" ] || { [ "$db_exists" = false ] && [[ "$current" == change-me* ]]; }; then
    set_value "$name" "$(random_hex)"
    generated=$((generated + 1))
  fi
done
if [ "$generated" -gt 0 ]; then
  echo "Wygenerowałem ${generated} haseł i sekretów w .env (plik jest poza Gitem)."
fi
