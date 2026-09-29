#!/usr/bin/env bash
# Live handshake v5 between macula-py and a macula station, on a real TLS
# session: macula-go's erlang_v5_station.escript (macula's own macula_peering
# on macula_quic, in macula's pinned CI image) and a macula-py pool dialling it
# (pyv5link.py). Each side derives the session binding from its own TLS
# exporter, so a label, context or exporter that differs fails the handshake.
# The station probes the link with liveness_ping every 500 ms for the hold.
# Passes when the station saw a v5 connection, no v4 one, and every
# connection end drained (the pool's GOODBYE), and the pool held its link.
#
#   eval "$(scripts/build_native.sh)"   # libmacula and build/macula-go
#   MACULA_BUILD=<compiled macula, 13.2.0 or later> scripts/interop/v5.sh [pq_hybrid|pq_pure]
#
# PYTHON and PODMAN_CGROUP_PARENT as in sealed.sh.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70}"
profile="${1:-pq_hybrid}"
python="${PYTHON:-python}"
interop="$root/build/macula-go/scripts/interop"
: "${MACULA_BUILD:?a compiled macula, 13.2.0 or later}"
[ -f "$interop/erlang_v5_station.escript" ] || { echo "v5.sh: no $interop/erlang_v5_station.escript; run scripts/build_native.sh" >&2; exit 1; }
work="$(mktemp -d)"
name="macula-py-v5-$$"
cleanup() {
  podman rm -f "$name" > /dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

podman run --rm --name "$name" --network host ${PODMAN_CGROUP_PARENT:+--cgroup-parent "$PODMAN_CGROUP_PARENT"} \
  -v "$MACULA_BUILD:/macula:ro" -v "$interop:/interop:ro" \
  "$image" escript /interop/erlang_v5_station.escript /macula/_build/default/lib/macula "$profile" 20 \
  > "$work/station.out" 2>&1 < /dev/null &
station_pid=$!
for _ in $(seq 1 300); do
  grep -q '^station ' "$work/station.out" 2> /dev/null && break
  sleep 0.2
done
if ! grep -q '^station ' "$work/station.out"; then
  echo "v5.sh: the macula station did not start:" >&2
  cat "$work/station.out" >&2
  exit 1
fi
read -r _ host port node < <(grep -m1 '^station ' "$work/station.out")
echo "== $profile: macula-py's pool to a macula station ($host:$port)"
link=0
$python "$root/scripts/interop/pyv5link.py" "$host" "$port" "$node" "$profile" 5 || link=$?
wait "$station_pid" || true
echo "== $profile: the macula station"
cat "$work/station.out"
grep -q '^verdict: PASS' "$work/station.out" && [ "$link" -eq 0 ]
