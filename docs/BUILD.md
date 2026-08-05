# Building and distributing Loom

## Platforms

| OS | Architectures | Artifact |
|----|---------------|----------|
| Linux | amd64, arm64 | `loom-<ver>-linux-<arch>` |
| macOS | amd64, arm64 | `loom-<ver>-darwin-<arch>` |
| Windows | amd64, arm64 | `loom-<ver>-windows-<arch>.exe` |

All builds use **`CGO_ENABLED=0`** (pure Go: modernc sqlite, pgx, gRPC).

## Local

```bash
# This machine
make build                 # → bin/loom

# All OS/arch
# VERSION defaults to contents of ./VERSION (currently 0.1.0)
make release                 # → dist/ + SHA256SUMS

# Install local dist binary (macOS/Linux)
./scripts/install.sh --from-dist --prefix "$HOME/.local"
```

Windows: copy `dist/loom-*-windows-amd64.exe` to a directory on `PATH` as `loom.exe`.

Version source of truth: root **`VERSION`** file (semver, no `v` prefix).  
Git tags use a leading `v` (e.g. `v0.1.0`). See `CHANGELOG.md`.

## Docker (Linux)

```bash
VERSION=$(tr -d '[:space:]' < VERSION)
docker build \
  --build-arg VERSION=$VERSION \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  -t loom:$VERSION .

docker run --rm -p 8080:8080 \
  -e LOOM_ENV=development \
  loom:$VERSION serve --addr=:8080
```

Multi-arch (requires buildx):

```bash
VERSION=$(tr -d '[:space:]' < VERSION)
docker buildx build --platform linux/amd64,linux/arm64 \
  -t your-registry/loom:$VERSION --push .
```

Production containers **must** set:

```text
LOOM_ENV=production
LOOM_DISABLE_DEMO_PRINCIPALS=true
LOOM_REQUIRE_DURABLE=true
LOOM_JWT_SECRET=…
LOOM_DATABASE_URL=…
```

## GitHub Releases

1. Bump `VERSION` and `CHANGELOG.md`
2. Commit, then tag: `git tag v$(tr -d '[:space:]' < VERSION) && git push origin v0.1.0`
3. Workflow `.github/workflows/release.yml` runs tests, cross-compiles, uploads assets + `SHA256SUMS`.

## Verify a download

```bash
shasum -a 256 -c SHA256SUMS
./loom-0.1.0-darwin-arm64 version
```
