#!/usr/bin/env bash
# Downloads macula-go's released C ABI libraries for the tag in
# abi/MACULA_GO_REF ("<tag> <commit sha>", and the tag must still be that
# commit) into DEST (default build/native), and uses none that
# fails a check: every file must match the release's SHA256SUMS and carry a
# build provenance attestation from macula-io/macula-go, and the release's
# macula.h must be abi/macula.h. Needs gh (GH_TOKEN) and sha256sum.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
read -r tag sha < "$root/abi/MACULA_GO_REF"
dest="${1:-$root/build/native}"
files=(libmacula-linux-x64.so libmacula-linux-arm64.so libmacula-macos-x64.dylib libmacula-macos-arm64.dylib macula-windows-x64.dll macula.h)

case "$tag" in
  v*) ;;
  *) echo "fetch_native: abi/MACULA_GO_REF is $tag, not a release tag; a release binds released libraries only" >&2; exit 1 ;;
esac

tagged="$(git ls-remote https://github.com/macula-io/macula-go "refs/tags/$tag^{}" "refs/tags/$tag" | awk 'NR==1 || /\^\{\}$/ {c=$1} END {print c}')"
if [ "$tagged" != "$sha" ]; then
  echo "fetch_native: macula-go $tag is $tagged, abi/MACULA_GO_REF records $sha" >&2
  exit 1
fi

rm -rf "$dest"; mkdir -p "$dest"
patterns=(-p SHA256SUMS); for f in "${files[@]}"; do patterns+=(-p "$f"); done
gh release download "$tag" --repo macula-io/macula-go --dir "$dest" "${patterns[@]}"

(cd "$dest"
  for f in "${files[@]}"; do
    grep -E "^[0-9a-f]{64}  $f\$" SHA256SUMS > /dev/null || { echo "fetch_native: $f is not in SHA256SUMS" >&2; exit 1; }
  done
  sha256sum --check --strict --ignore-missing SHA256SUMS
  for f in "${files[@]}"; do
    gh attestation verify "$f" --repo macula-io/macula-go > /dev/null
    echo "attested: $f"
  done)

cmp "$dest/macula.h" "$root/abi/macula.h" || { echo "fetch_native: $tag's macula.h is not abi/macula.h" >&2; exit 1; }
