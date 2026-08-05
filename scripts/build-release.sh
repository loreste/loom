#!/usr/bin/env bash
# Cross-compile loom CLI for Windows, macOS, and Linux.
#
# Usage:
#   ./scripts/build-release.sh              # → dist/
#   VERSION=0.1.0 ./scripts/build-release.sh
#   OUT=./artifacts ./scripts/build-release.sh
#
# Pure Go (CGO_ENABLED=0): modernc sqlite, pgx, grpc — no C toolchain required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-$ROOT/dist}"
# Prefer explicit VERSION, then VERSION file, then git tag, then dev.
if [[ -z "${VERSION:-}" ]]; then
  if [[ -f "$ROOT/VERSION" ]]; then
    VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
  elif git describe --tags --exact-match 2>/dev/null | grep -q .; then
    VERSION="$(git describe --tags --exact-match 2>/dev/null | sed 's/^v//')"
  else
    VERSION="dev"
  fi
fi
VERSION="${VERSION#v}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

# os/arch pairs shipped by default
TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

mkdir -p "$OUT"
rm -f "$OUT"/loom-* "$OUT"/SHA256SUMS 2>/dev/null || true

echo "Building loom ${VERSION} (commit=${COMMIT})"
echo "Output: ${OUT}"
echo

for target in "${TARGETS[@]}"; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  name="loom-${VERSION}-${GOOS}-${GOARCH}"
  if [[ "$GOOS" == "windows" ]]; then
    name="${name}.exe"
  fi
  dest="${OUT}/${name}"
  echo "→ ${GOOS}/${GOARCH}  ${name}"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$dest" ./cmd/loom
done

echo
echo "Checksums:"
(
  cd "$OUT"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 loom-* | tee SHA256SUMS
  else
    sha256sum loom-* | tee SHA256SUMS
  fi
)

echo
echo "Done. Artifacts in ${OUT}/"
ls -lh "$OUT"
