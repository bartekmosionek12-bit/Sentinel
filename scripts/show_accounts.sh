#!/usr/bin/env bash
# Wypisuje konta do logowania z hasłami i kodem TOTP (z data/demo-credentials.env, poza Gitem).
# Wołają go start.sh i start_live.sh na samym końcu, żeby dane były widoczne bez szukania.
set -euo pipefail
cd "$(dirname "$0")/.."
CREDS=data/demo-credentials.env
[ -f "$CREDS" ] || { echo "Brak $CREDS: konta jeszcze nie powstały (scripts/demo_users.sh)." >&2; exit 0; }
get() { grep -E "^$1=" "$CREDS" | tail -n1 | cut -d= -f2-; }
TOTP=$(get DEMO_ADMIN_TOTP_BASE32)
echo
echo "Konta (logowanie: http://localhost:8080/admin/ , hasło + kod TOTP):"
printf '  %-11s %-34s %s\n' "LOGIN" "ROLA" "HASŁO"
printf '  %-11s %-34s %s\n' admin "Administracja" "$(get DEMO_ADMIN_PASSWORD)"
printf '  %-11s %-34s %s\n' editor "Dodawanie, usuwanie, modyfikacja" "$(get DEMO_EDITOR_PASSWORD)"
printf '  %-11s %-34s %s\n' modifier "Modyfikacja i odczyt" "$(get DEMO_MODIFIER_PASSWORD)"
printf '  %-11s %-34s %s\n' viewer "Odczyt" "$(get DEMO_VIEWER_PASSWORD)"
printf '  %-11s %-34s %s\n' analityk "editor (warstwy z delegacji)" "$(get DEMO_ANALYST_PASSWORD)"
printf '  %-11s %-34s %s\n' operator "modifier (warstwy z delegacji)" "$(get DEMO_OPERATOR_PASSWORD)"
printf '  %-11s %-34s %s\n' redaktor "editor" "$(get DEMO_REDAKTOR_PASSWORD)"
printf '  %-11s %-34s %s\n' obserwator "viewer" "$(get DEMO_OBSERWATOR_PASSWORD)"
echo
echo "  Kod TOTP (wspólny dla wszystkich kont): dodaj w aplikacji uwierzytelniającej sekret"
echo "    ${TOTP}"
echo "  albo link: otpauth://totp/Sentinel%20ASI:demo?secret=${TOTP}&issuer=Sentinel%20ASI"
echo "  Te same dane: ${CREDS}"
