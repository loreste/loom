#!/usr/bin/env sh
set -eu

repository=${LOOM_REPOSITORY:-${GITHUB_REPOSITORY:-}}
version=${LOOM_VERSION:-}
install_dir=${LOOM_INSTALL_DIR:-"$HOME/.local/bin"}

if [ -z "$repository" ]; then
  echo "set LOOM_REPOSITORY to the GitHub owner/repository" >&2
  exit 1
fi
if [ -z "$version" ]; then
	  echo "set LOOM_VERSION to an exact release tag (for example, v0.1.4)" >&2
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
mkdir -p "$install_dir"
curl --fail --location --show-error --silent "$base/$asset" --output "$install_dir/loom"
chmod 0755 "$install_dir/loom"
echo "installed Loom to $install_dir/loom"
