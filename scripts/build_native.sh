#!/usr/bin/env bash
# Builds macula-go's shared C ABI library into src/macula_py/_native/ and its
# teststation into build/, both from the macula-go ref in abi/MACULA_GO_REF,
# and checks that abi/macula.h is that ref's header.
#
# MACULA_GO_DIR: a macula-go checkout to build from (default: a clone in
# build/macula-go). Needs Go >= 1.26 and a C compiler (cgo).
# Prints the export lines for the tests: eval "$(scripts/build_native.sh)".
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ref="$(tr -d '[:space:]' < "$root/abi/MACULA_GO_REF")"
src="${MACULA_GO_DIR:-$root/build/macula-go}"

if [ ! -d "$src/.git" ]; then
  git clone --quiet git@github.com:macula-io/macula-go.git "$src" 2>/dev/null \
    || git clone --quiet https://github.com/macula-io/macula-go.git "$src"
fi
git -C "$src" fetch --quiet origin
git -C "$src" -c advice.detachedHead=false checkout --quiet "$ref"

if ! cmp -s "$src/cabi/macula.h" "$root/abi/macula.h"; then
  echo "build_native: abi/macula.h differs from cabi/macula.h at macula-go $ref" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux) lib=libmacula.so ;;
  Darwin) lib=libmacula.dylib ;;
  MINGW*|MSYS*|CYGWIN*) lib=macula.dll ;;
  *) echo "build_native: unsupported platform $(uname -s)" >&2; exit 1 ;;
esac

mkdir -p "$root/src/macula_py/_native" "$root/build"
(cd "$src" && CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -o "$root/src/macula_py/_native/$lib" ./cabi)
rm -f "$root/src/macula_py/_native/"*.h
(cd "$src" && go build -trimpath -o "$root/build/teststation" ./teststation/cmd/teststation)

echo "export MACULA_TESTSTATION=$root/build/teststation"
