#!/usr/bin/env sh
set -eu

dist_dir=${1:-dist}
checksums="$dist_dir/SHA256SUMS"

if [ ! -f "$checksums" ]; then
  echo "missing release checksum manifest: $checksums" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1"; }
else
  echo "no SHA-256 verification command available" >&2
  exit 1
fi

verified=0
while IFS='  ' read -r digest asset; do
  [ -n "$digest" ] || continue
  [ -n "$asset" ] || { echo "malformed checksum entry" >&2; exit 1; }
  case "$asset" in
    /*|*../*) echo "unsafe checksum asset name: $asset" >&2; exit 1 ;;
  esac
  path="$dist_dir/$asset"
  [ -f "$path" ] || { echo "checksum asset is missing: $asset" >&2; exit 1; }
  actual=$(checksum "$path" | awk '{print $1}')
  [ "$actual" = "$digest" ] || { echo "checksum mismatch: $asset" >&2; exit 1; }
  case "$asset" in
    SHA256SUMS) ;;
    *)
      [ -f "$path.sigstore.json" ] || { echo "missing Sigstore bundle: $asset.sigstore.json" >&2; exit 1; }
      verified=$((verified + 1))
      ;;
  esac
done < "$checksums"

[ "$verified" -gt 0 ] || { echo "no publishable release assets verified" >&2; exit 1; }
echo "verified $verified release assets"
