#!/usr/bin/env bash
# Install the loom CLI for the current OS/arch (macOS or Linux).
#
# From a release (GitHub):
#   curl -fsSL https://raw.githubusercontent.com/<org>/loom/main/scripts/install.sh | bash
#
# From a local dist/ after make release:
#   ./scripts/install.sh --from-dist
#   VERSION=0.3.0 ./scripts/install.sh --from-dist --prefix=$HOME/.local
#
# Windows: download loom-*-windows-amd64.exe from the release assets and rename to loom.exe.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
VERSION="${VERSION:-}"
FROM_DIST=0
REPO_BASE="${LOOM_INSTALL_BASE:-}"

usage() {
  cat <<'EOF'
Usage: install.sh [options]
  --from-dist     Install from ./dist (after make release)
  --prefix DIR    Install prefix (default /usr/local → $PREFIX/bin/loom)
  --version VER   Version string matching dist artifact (e.g. 0.3.0 or v0.3.0)
  -h, --help      Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-dist) FROM_DIST=1; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  msys*|mingw*|cygwin*)
    echo "Windows: download the .exe from GitHub Releases (see README)." >&2
    exit 1
    ;;
  *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac

if [[ -z "$VERSION" ]]; then
  if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
    VERSION="${GITHUB_REF_NAME#v}"
  elif command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    VERSION="$(git describe --tags --always 2>/dev/null | sed 's/^v//')"
  else
    VERSION="0.3.0"
  fi
fi
VERSION="${VERSION#v}"

NAME="loom-${VERSION}-${OS}-${ARCH}"
DEST_DIR="${PREFIX}/bin"
DEST="${DEST_DIR}/loom"

mkdir -p "$DEST_DIR"

if [[ "$FROM_DIST" -eq 1 ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  SRC="${ROOT}/dist/${NAME}"
  if [[ ! -f "$SRC" ]]; then
    echo "missing $SRC — run: VERSION=${VERSION} make release" >&2
    exit 1
  fi
  install -m 0755 "$SRC" "$DEST"
else
  if [[ -z "$REPO_BASE" ]]; then
    echo "Set LOOM_INSTALL_BASE to a release URL prefix, e.g." >&2
    echo "  LOOM_INSTALL_BASE=https://github.com/<org>/loom/releases/download/v${VERSION}" >&2
    echo "Or use: $0 --from-dist" >&2
    exit 1
  fi
  URL="${REPO_BASE%/}/loom-${VERSION}-${OS}-${ARCH}"
  TMP="$(mktemp)"
  trap 'rm -f "$TMP"' EXIT
  echo "Downloading $URL"
  curl -fsSL "$URL" -o "$TMP"
  install -m 0755 "$TMP" "$DEST"
fi

echo "Installed: $DEST"
"$DEST" version || true
