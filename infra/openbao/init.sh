#!/bin/sh
# Jednorazowa usługa `bao-init` (uruchamiana przy każdym `docker compose up`, idempotentna):
#   1. inicjalizacja OpenBao (jeden klucz rozpieczętowania, tylko demo) i rozpieczętowanie,
#   2. silnik `ssh` w trybie CA i rola `sentinel-scanner`: certyfikat na 15 minut, tylko
#      użytkownik `sentinel-scan`, bez rozszerzeń (bez PTY i przekierowań),
#   3. AppRole `mcp-scanner` z polityką „tylko podpis”, token na 15 minut,
#   4. AppRole `killswitch` (osobny punkt montowania) z polityką „tylko revoke-prefix”
#      dla tokenów mcp-scanner; używa go API przy kill switchu,
#   5. pliki dla usług: approle.json (mcp-scanner), killswitch/approle.json (api) i ca.pub
#      (hosty demo-lab).
#
# Klucz rozpieczętowania i token root leżą w wolumenie `openbao-init` dostępnym wyłącznie
# dla tej usługi. To uproszczenie demo opisane w README (produkcja: auto-unseal, KMS/HSM).
set -eu

export BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
STATE=/bao-state
APPROLE_OUT=/out/approle
KILL_OUT=/out/killswitch
CA_OUT=/out/ca

echo "bao-init: czekam na OpenBao"
for _ in $(seq 1 60); do
  set +e
  bao status >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -ne 1 ] && break
  sleep 1
done

if [ ! -s "$STATE/init.txt" ]; then
  bao operator init -key-shares=1 -key-threshold=1 > "$STATE/init.txt"
  chmod 600 "$STATE/init.txt"
  echo "bao-init: OpenBao zainicjalizowany"
fi
UNSEAL=$(awk '/Unseal Key 1:/ {print $4}' "$STATE/init.txt")
BAO_TOKEN=$(awk '/Initial Root Token:/ {print $4}' "$STATE/init.txt")
export BAO_TOKEN
bao operator unseal "$UNSEAL" >/dev/null

if ! bao secrets list | grep -q '^ssh-client-signer/'; then
  bao secrets enable -path=ssh-client-signer ssh >/dev/null
fi
if ! bao read ssh-client-signer/config/ca >/dev/null 2>&1; then
  bao write ssh-client-signer/config/ca generate_signing_key=true key_type=ed25519 >/dev/null
fi
bao write ssh-client-signer/roles/sentinel-scanner - < /policies/ssh-role.json >/dev/null
bao policy write mcp-scanner /policies/mcp-scanner.hcl >/dev/null
bao policy write killswitch /policies/killswitch.hcl >/dev/null

if ! bao auth list | grep -q '^approle/'; then
  bao auth enable approle >/dev/null
fi
bao write auth/approle/role/mcp-scanner \
  token_policies=mcp-scanner token_ttl=15m token_max_ttl=15m \
  secret_id_ttl=0 secret_id_num_uses=0 >/dev/null

if ! bao auth list | grep -q '^killswitch/'; then
  bao auth enable -path=killswitch approle >/dev/null
fi
bao write auth/killswitch/role/killswitch \
  token_policies=killswitch token_ttl=1m token_max_ttl=1m \
  secret_id_ttl=0 secret_id_num_uses=0 >/dev/null

ROLE_ID=$(bao read -field=role_id auth/approle/role/mcp-scanner/role-id)
SECRET_ID=$(bao write -f -field=secret_id auth/approle/role/mcp-scanner/secret-id)
umask 027
printf '{"role_id": "%s", "secret_id": "%s"}\n' "$ROLE_ID" "$SECRET_ID" > "$APPROLE_OUT/approle.json.tmp"
mv "$APPROLE_OUT/approle.json.tmp" "$APPROLE_OUT/approle.json"
chmod 0444 "$APPROLE_OUT/approle.json"
KILL_ROLE=$(bao read -field=role_id auth/killswitch/role/killswitch/role-id)
KILL_SECRET=$(bao write -f -field=secret_id auth/killswitch/role/killswitch/secret-id)
printf '{"role_id": "%s", "secret_id": "%s"}\n' "$KILL_ROLE" "$KILL_SECRET" > "$KILL_OUT/approle.json.tmp"
mv "$KILL_OUT/approle.json.tmp" "$KILL_OUT/approle.json"
chmod 0444 "$KILL_OUT/approle.json"
bao read -field=public_key ssh-client-signer/config/ca > "$CA_OUT/ca.pub.tmp"
chmod 0444 "$CA_OUT/ca.pub.tmp"
mv -f "$CA_OUT/ca.pub.tmp" "$CA_OUT/ca.pub"
echo "bao-init: gotowe (CA SSH, rola sentinel-scanner 15 min, AppRole mcp-scanner i killswitch)"
