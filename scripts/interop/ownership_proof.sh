#!/usr/bin/env bash
# macula-py's ownership proofs through mcl_om's own verifier: signs a payload
# with macula-py, sends it the real way to scripts/interop/capture, and has
# macula-go's scripts/interop/erlang_ownership_proof.escript verify accept it
# once, refuse it with one field changed (bad_signature) and refuse it sent
# again (replayed), in macula's pinned CI image.
#
#   MACULA_BUILD=<macula checkout, compiled> MCL_OM_SRC=<dir of mcl_om's three proof modules> \
#     scripts/interop/ownership_proof.sh
#
# MCL_OM_SRC holds mcl_om_wire, mcl_om_ownership_proof_replay and
# mcl_om_ownership_proof from mcl-om 0.32.0 (91e59d87). Needs
# MACULA_TESTSTATION and build/macula-go (scripts/build_native.sh), Go and
# podman. The proof carries the time it was signed, so the two halves run
# back to back.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${MACULA_CI_IMAGE:-ghcr.io/macula-io/macula-ci-otp@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70}"
: "${MACULA_BUILD:?a compiled macula checkout}" "${MCL_OM_SRC:?mcl_om 0.32.0 proof modules}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

(cd "$root/scripts/interop/capture" && go build -o "$work/capture" .)
python "$root/scripts/interop/ownership_proof.py" "$work/capture" "$work/payload.txt"
podman run --rm --name "macula-py-ownership-proof-$$" \
  -v "$MACULA_BUILD:/macula:ro" -v "$MCL_OM_SRC:/mcl-om:ro" \
  -v "$root/build/macula-go/scripts/interop:/interop:ro" -v "$work:/work:ro" \
  "$image" escript /interop/erlang_ownership_proof.escript verify /macula/_build/default/lib/macula/ebin /mcl-om /work/payload.txt
