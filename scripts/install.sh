#!/usr/bin/env sh
# Install a verified Loom release binary (Linux/macOS).
# Example:
#   LOOM_REPOSITORY=loreste/loom LOOM_VERSION=v1.0.1 sh scripts/install.sh
# Optional: LOOM_INSTALL_DIR=$HOME/.local/bin (default)
set -eu


repository=${LOOM_REPOSITORY:-${GITHUB_REPOSITORY:-}}
version=${LOOM_VERSION:-}
install_dir=${LOOM_INSTALL_DIR:-"$HOME/.local/bin"}

if [ -z "$repository" ]; then
  echo "set LOOM_REPOSITORY to the GitHub owner/repository" >&2
  exit 1
fi
if [ -z "$version" ]; then
  echo "set LOOM_VERSION to an exact release tag (for example, vX.Y.Z)" >&2
  exit 1
fi

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) os=linux; arch=amd64;;
  Linux:aarch64|Linux:arm64) os=linux; arch=arm64;;
  Darwin:x86_64) os=darwin; arch=amd64;;
  Darwin:arm64) os=darwin; arch=arm64;;
  *) echo "unsupported platform: $(uname -s)/$(uname -m)" >&2; exit 1;;
esac

asset="loom-${version}-${os}-${arch}"
base="https://github.com/${repository}/releases/download/${version}"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/loom-install.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

mkdir -p "$install_dir"
curl --fail --location --show-error --silent "$base/$asset" --output "$tmp_dir/$asset"
curl --fail --location --show-error --silent "$base/SHA256SUMS" --output "$tmp_dir/SHA256SUMS"

expected=$(awk -v target="$asset" '$2 == target { print $1; exit }' "$tmp_dir/SHA256SUMS")
if [ -z "$expected" ]; then
  echo "release checksum is missing for $asset" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp_dir/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp_dir/$asset" | awk '{print $1}')
else
  echo "neither sha256sum nor shasum is available to verify the release" >&2
  exit 1
fi
if [ "$actual" != "$expected" ]; then
  echo "release checksum verification failed for $asset" >&2
  exit 1
fi

install -m 0755 "$tmp_dir/$asset" "$install_dir/loom"
echo "installed Loom to $install_dir/loom"
