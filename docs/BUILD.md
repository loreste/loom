# Build and release

Loom can be embedded without a separate service. The repository also builds the
CLI, container, cross-platform release binaries, and SDKs from the source tree.

## Local checks

```bash
make test
make test-race
make vet
make build
make fuzz FUZZ_TIME=15s
go mod verify
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.22.8 -exclude-dir=adapters/grpc/gen ./...
```

The `sdk` Make target is informational. Language-specific SDK checks run in CI
and are documented under `sdk/`.

## Build release binaries

The root [`VERSION`](../VERSION) file is the default version source:

```bash
make release
```

Artifacts are written to `dist/`:

```text
loom-VERSION-linux-amd64
loom-VERSION-linux-arm64
loom-VERSION-darwin-amd64
loom-VERSION-darwin-arm64
loom-VERSION-windows-amd64.exe
loom-VERSION-windows-arm64.exe
SHA256SUMS
```

Override `LOOM_VERSION`, `LOOM_COMMIT`, `LOOM_BUILD_DATE`, `DIST_DIR`, or
`VERSION_FILE` when a build pipeline supplies them. Set `GOOS`, `GOARCH`, or
`LOOM_TARGETS` for a smaller target set. Runtime credentials, database URLs,
identity configuration, tenant policy, and application secrets are never
embedded in release artifacts.

## Verify an installed release

The installer requires an exact release tag and verifies the downloaded binary
against the release's `SHA256SUMS` file:

```bash
LOOM_REPOSITORY=loreste/loom \
LOOM_VERSION=v1.0.1 \
  sh scripts/install.sh
```

For independent verification, download the binary and checksum manifest from
the release page and run:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Release binaries also have keyless Cosign bundles and GitHub build-provenance
attestations. Verify those with the trust policy required by your organization
before promoting an artifact into production. An application may additionally
require a pinned signing identity and OIDC issuer for Cosign verification.

## Docker image

```bash
docker build \
  --build-arg VERSION="$(tr -d '[:space:]' VERSION)" \
  -t loom:local .
```

The image builds the CLI with CGO disabled and runs as a non-root user from a
distroless base image. It contains no demo credentials or application secrets.
The release workflow publishes the official image to GHCR with Cosign signing,
SBOM, and provenance. Deployments still choose their own retention, admission,
and promotion policy.

## GitHub release workflow

Pushing a tag matching `v*` runs the release workflow. It:

1. verifies the tag points at its exact commit;
2. waits for successful `ci`, `security`, `dependency-review`, and
   `container-scan` workflows for that same commit;
3. builds Linux, macOS, and Windows binaries for amd64 and arm64;
4. creates a CycloneDX SBOM and SHA-256 checksum manifest;
5. creates keyless Cosign signature bundles and build-provenance attestations;
6. publishes all release evidence with the GitHub release.

The separate SDK publication workflow checks exact version alignment and then
attempts to publish the Python, npm, and Rust packages. Publication depends on
registry-side trusted-publisher configuration; a configured workflow does not
mean that a package has been published. See [`RELEASES.md`](RELEASES.md).

## Security gates

The merge and release gates include blocking govulncheck, gosec, CodeQL, secret
scanning, dependency review, SDK validation, PostgreSQL integration, adapter
contract tests, SBOM generation, and container scanning. Unfixed container
findings are not silently suppressed; the scan fails on configured HIGH and
CRITICAL findings and remains visible for scheduled review.

## Build metadata

The CLI accepts link-time values for version, commit, and build date. A normal
development build reports `unknown` for metadata that was not supplied by the
build pipeline.
