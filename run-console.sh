#!/usr/bin/env bash
# Launch the TETRA KMF operator console (local, login-protected).
set -euo pipefail
CONF="$HOME/.config/tetra-kmf"
ENVF="$CONF/console.env"
BIN="$HOME/Documents/tetra-kmf/target/release/kmfctl"
[ -f "$ENVF" ] || { echo "missing $ENVF (holds the secrets)"; exit 1; }
# shellcheck disable=SC1090
source "$ENVF"
: "${TETRA_KMF_MASTER_KEY:?set in console.env}"
: "${TETRA_KMF_CONSOLE_PASSWORD:?set in console.env}"
KMF_DB="${KMF_DB:-$CONF/kmf-db.json}"
SWMI_URL="${SWMI_URL:-https://flowstation.local}"
export TETRA_KMF_MASTER_KEY TETRA_KMF_CONSOLE_PASSWORD TETRA_KMF_SWMI_PASSWORD
[ -f "$KMF_DB" ] || "$BIN" --db "$KMF_DB" init
echo "KMF console → http://127.0.0.1:8088  (user: admin)"
exec "$BIN" --db "$KMF_DB" serve --bind 127.0.0.1:8088 --swmi "$SWMI_URL" --insecure
