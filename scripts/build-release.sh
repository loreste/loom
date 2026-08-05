#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version_file=${VERSION_FILE:-"$root_dir/VERSION"}
dist_dir=${DIST_DIR:-"$root_dir/dist"}
version=${LOOM_VERSION:-$(tr -d '[:space:]' < "$version_file")}
commit=${LOOM_COMMIT:-unknown}
build_date=${LOOM_BUILD_DATE:-unknown}

if [ -z "$version" ]; then
  echo "release version is empty; set LOOM_VERSION or populate VERSION" >&2
  exit 1
fi

mkdir -p "$dist_dir"
targets=${LOOM_TARGETS:-"linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"}
[ -n "${GOOS:-}" ] && [ -n "${GOARCH:-}" ] && targets="$GOOS/$GOARCH"
for target in $targets; do
  os=${target%/*}
  arch=${target#*/}
  suffix=
  [ "$os" = windows ] && suffix=.exe
  out="$dist_dir/loom-${version}-${os}-${arch}${suffix}"
  echo "building $out"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath \
      -ldflags "-s -w -X main.version=$version -X main.commit=$commit -X main.date=$build_date" \
      -o "$out" "$root_dir/cmd/loom"
done
