#!/usr/bin/env bash
# Konto awaryjne (break-glass): nadaje nowe hasło i sekret TOTP kontu `breakglass-admin`.
#
# Wynik jest wypisywany RAZ na ekran i nigdzie nie zapisywany. Przechowuj go poza systemem
# (zaklejona koperta, sejf, menedżer haseł zespołu); od Etapu 5 trafi do sejfu OpenBao.
# Każde logowanie tym kontem zapisuje w audycie `breakglass_used` i wysyła alert.
# Ponowne uruchomienie unieważnia poprzednie hasło i sekret.
set -euo pipefail
cd "$(dirname "$0")/.."

read -r -p "Nadać nowe dane konta awaryjnego? Poprzednie przestaną działać [t/N] " answer
[ "$answer" = "t" ] || { echo "Przerwano."; exit 1; }

PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
TOTP_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(15))")
TOTP_BASE32=$(python3 -c "import base64,sys; print(base64.b32encode(sys.argv[1].encode()).decode().rstrip('='))" "$TOTP_SECRET")

USER_JSON=$(PASSWORD="$PASSWORD" TOTP_SECRET="$TOTP_SECRET" python3 - <<'PY'
import json, os
print(json.dumps({"ifResourceExists": "OVERWRITE", "users": [{
    "username": "breakglass-admin", "firstName": "Konto", "lastName": "awaryjne",
    "enabled": True, "realmRoles": ["admin"], "requiredActions": [],
    "credentials": [
        {"type": "password", "value": os.environ["PASSWORD"], "temporary": False},
        {"type": "otp", "userLabel": "break-glass",
         "secretData": json.dumps({"value": os.environ["TOTP_SECRET"]}),
         "credentialData": json.dumps({"subType": "totp", "digits": 6, "period": 30,
                                       "algorithm": "HmacSHA1", "counter": 0})},
    ],
}]}))
PY
)

# Tuż po starcie Keycloak bywa jeszcze niegotowy (503), stąd kilka prób.
for attempt in 1 2 3 4 5 6; do
  if docker compose exec -T keycloak sh -c '/opt/keycloak/bin/kcadm.sh config credentials \
      --server http://localhost:8080/auth --realm master \
      --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD"' >/dev/null 2>&1 \
    && printf '%s' "$USER_JSON" | docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh \
      create partialImport -r sentinel -s ifResourceExists=OVERWRITE -f - >/dev/null; then
    break
  fi
  [ "$attempt" = 6 ] && { echo "Keycloak nie przyjął kont (sprawdź: docker compose logs keycloak)" >&2; exit 1; }
  sleep 10
done

cat <<OUT

Konto awaryjne: breakglass-admin
Hasło:          ${PASSWORD}
Sekret TOTP:    ${TOTP_BASE32}
otpauth://totp/Sentinel%20ASI:breakglass-admin?secret=${TOTP_BASE32}&issuer=Sentinel%20ASI

Zapisz te dane poza systemem. Nie zostały nigdzie zapisane.
OUT
