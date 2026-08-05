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
VERSION=0.3.0 make release # → dist/ + SHA256SUMS

# Install local dist binary (macOS/Linux)
./scripts/install.sh --from-dist --prefix "$HOME/.local"
```

Windows: copy `dist/loom-*-windows-amd64.exe` to a directory on `PATH` as `loom.exe`.

## Docker (Linux)

```bash
docker build \
  --build-arg VERSION=0.3.0 \
  --build-arg COMMIT=$(git rev-parse --short HEAD) \
  -t loom:0.3.0 .

docker run --rm -p 8080:8080 \
  -e LOOM_ENV=development \
  loom:0.3.0 serve --addr=:8080
```

Multi-arch (requires buildx):

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t your-registry/loom:0.3.0 --push .
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

1. Tag: `git tag v0.3.0 && git push origin v0.3.0`
2. Workflow `.github/workflows/release.yml` runs tests, cross-compiles, uploads assets + `SHA256SUMS`.

## Verify a download

```bash
shasum -a 256 -c SHA256SUMS
./loom-0.3.0-darwin-arm64 version
```
