#!/usr/bin/env sh
set -eu

dist_dir=${1:-dist}
output=${2:-"$dist_dir/SHA256SUMS"}

if [ ! -d "$dist_dir" ]; then
  echo "release artifact directory does not exist: $dist_dir" >&2
  exit 1
fi

tmp_file="$output.tmp.$$"
trap 'rm -f "$tmp_file"' EXIT INT TERM

(
  cd "$dist_dir"
  found=0
  for asset in loom-*; do
    [ -f "$asset" ] || continue
    case "$asset" in
      *.sigstore.json|*sbom*.json|SHA256SUMS) continue ;;
    esac
    found=1
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$asset"
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "$asset"
    else
      echo "neither sha256sum nor shasum is available" >&2
      exit 1
    fi
  done
  [ "$found" -eq 1 ] || { echo "no release binaries found in $dist_dir" >&2; exit 1; }
) | LC_ALL=C sort > "$tmp_file"

mv "$tmp_file" "$output"
trap - EXIT INT TERM
echo "wrote $output"
