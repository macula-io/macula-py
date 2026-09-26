#!/usr/bin/env bash
# ONE live check of macula-py against a macula 12 station, with a key
# generated for the run and never saved. Defaults: helsinki and the io.macula
# realm; the realm key is io.macula's PUBLIC half, read from mcl-echo's header.
# Override any MACULA_PY_LIVE_* variable to point elsewhere.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
echo_hrl="${MCL_ECHO_REALM_HRL:-$HOME/work/github.com/macula-services/mcl-echo/apps/mcl_echo/include/mcl_echo_io_macula.hrl}"

realm_key_from_hrl() {
  python3 - "$1" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
body = text[text.index("MCL_ECHO_REAL_REALM_KEY"):]
body = body[:body.index(">>")]
print("".join(re.findall(r"16#([0-9A-Fa-f]+):\d+", body)).lower())
PY
}

export MACULA_PY_LIVE=1
export MACULA_PY_LIVE_SEED="${MACULA_PY_LIVE_SEED:-station-fi-helsinki.macula.io:4433}"
export MACULA_PY_LIVE_STATION_ID="${MACULA_PY_LIVE_STATION_ID:-004d1f470097ccf8826ce291900e882fdb1f20375e53901facaec0f23eb4efd8}"
export MACULA_PY_LIVE_REALM="${MACULA_PY_LIVE_REALM:-abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1}"
export MACULA_PY_LIVE_REALM_KEY="${MACULA_PY_LIVE_REALM_KEY:-$(realm_key_from_hrl "$echo_hrl")}"

key_hex_len=${#MACULA_PY_LIVE_REALM_KEY}
[ "$key_hex_len" -gt 0 ] || { echo "live_check: realm key is empty" >&2; exit 1; }
echo "realm key: $(( key_hex_len / 2 )) bytes"

cd "$here"
date -u +"live start %FT%TZ"
timeout 300 python -m pytest -p no:cacheprovider tests/live -v
date -u +"live end %FT%TZ"
