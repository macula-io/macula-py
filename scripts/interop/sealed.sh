#!/usr/bin/env bash
# Sealed calls and streams across macula 13 and macula-py, both ways, through
# macula-go's test station, each caller's seal report checked: an Erlang
# provider (named key, required) called and streamed to by pysealed.py; then a
# Python provider, called and streamed to by macula-go's
# erlang_sealed.escript, which also calls it clear at its station and must be
# refused sealed_required. The Erlang side runs in macula's pinned CI image.
#
#   eval "$(scripts/build_native.sh)"   # libmacula, MACULA_TESTSTATION and build/macula-go
#   MACULA_BUILD=<compiled macula, 13.1.0 or later> scripts/interop/sealed.sh [pq_hybrid|pq_pure]
#
# PYTHON runs pysealed.py (default python, with macula-py importable); it must
# reach the loopback the station listens on. PODMAN_CGROUP_PARENT, when set,
# is the Erlang container's --cgroup-parent.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70}"
profile="${1:-pq_hybrid}"
python="${PYTHON:-python}"
interop="$root/build/macula-go/scripts/interop"
: "${MACULA_BUILD:?a compiled macula, 13.1.0 or later}" "${MACULA_TESTSTATION:?eval \"\$(scripts/build_native.sh)\" first}"
[ -f "$interop/erlang_sealed.escript" ] || { echo "sealed.sh: no $interop/erlang_sealed.escript; run scripts/build_native.sh" >&2; exit 1; }
work="$(mktemp -d)"
erl_name="macula-py-sealed-$$"
cleanup() {
  podman rm -f "$erl_name" > /dev/null 2>&1 || true
  [ -n "${py_pid:-}" ] && kill "$py_pid" 2> /dev/null || true
  [ -n "${station_pid:-}" ] && kill "$station_pid" 2> /dev/null || true
  exec 3>&- || true
  rm -rf "$work"
}
trap cleanup EXIT

mkfifo "$work/stations.in"
"$MACULA_TESTSTATION" "$profile" < "$work/stations.in" > "$work/stations.out" &
station_pid=$!
exec 3> "$work/stations.in"

# first_line FILE PATTERN waits up to 180 s for a line of FILE matching PATTERN.
first_line() {
  for _ in $(seq 1 900); do
    line="$(grep -m1 -E "$2" "$1" 2> /dev/null || true)"
    [ -n "$line" ] && { echo "$line"; return 0; }
    sleep 0.2
  done
  echo "sealed.sh: no line matching $2 in $1" >&2
  cat "$1" >&2 || true
  return 1
}
info="$(first_line "$work/stations.out" '^\{')"
read -r host port station realm < <(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); s=d["stations"][0]; print(s["host"], s["port"], s["node_id"], d["realm_id"])' "$info")
erl() {
  podman run --rm --name "$erl_name" --network host ${PODMAN_CGROUP_PARENT:+--cgroup-parent "$PODMAN_CGROUP_PARENT"} \
    -e MACULA_OFF_REFUSED=1 -e MACULA_SEALED_PEER=py -e MACULA_SEAL_REPORT=1 \
    -v "$MACULA_BUILD:/macula:ro" -v "$interop:/interop:ro" \
    "$image" escript /interop/erlang_sealed.escript /macula/_build/default/lib/macula "$host" "$port" "$station" "$realm" "$profile" "$@"
}

echo "== $profile: an Erlang provider, a Python caller"
erl serve 180 > "$work/erlang.out" 2>&1 < /dev/null &
first_line "$work/erlang.out" '^serving' > /dev/null
provider="$(first_line "$work/erlang.out" '^node ' | awk '{print $2}')"
$python "$root/scripts/interop/pysealed.py" "$host:$port@$station" "$profile" "$realm" call "$provider"
podman rm -f "$erl_name" > /dev/null 2>&1 || true

echo "== $profile: a Python provider, an Erlang caller"
$python "$root/scripts/interop/pysealed.py" "$host:$port@$station" "$profile" "$realm" serve 180 > "$work/py.out" 2>&1 < /dev/null &
py_pid=$!
first_line "$work/py.out" '^serving' > /dev/null
provider="$(first_line "$work/py.out" '^node ' | awk '{print $2}')"
erl call "$provider" < /dev/null
echo "== $profile: both ways sealed, both reports sealed (Python)"
