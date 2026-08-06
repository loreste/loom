# Build and release

Loom can be embedded without a separate service. The repository also builds a
CLI, a Docker image, cross-platform release binaries, and SDK packages from the
source tree.

## Local checks

```bash
make test
make test-race
make vet
make build
make fuzz FUZZ_TIME=15s
```

The `sdk` Make target is informational; language-specific SDK checks are run by
the CI workflow and are documented in the SDK READMEs.

## Build a release binary

The root [`VERSION`](../VERSION) file is the default version source. Build all
release targets locally with:

```bash
make release
```

Artifacts are written to `dist/` as:

```text
loom-VERSION-linux-amd64
loom-VERSION-linux-arm64
loom-VERSION-darwin-amd64
loom-VERSION-darwin-arm64
loom-VERSION-windows-amd64.exe
loom-VERSION-windows-arm64.exe
```

Override `LOOM_VERSION`, `LOOM_COMMIT`, `LOOM_BUILD_DATE`, `DIST_DIR`, or
`VERSION_FILE` when a build pipeline supplies those values. Set `GOOS`,
`GOARCH`, or `LOOM_TARGETS` to build a smaller target set.

Runtime credentials, database URLs, identity configuration, tenant policy, and
application secrets are never embedded in release artifacts.

## Docker image

The Dockerfile builds the CLI with CGO disabled and runs it as a non-root user
from a distroless base image:

```bash
docker build \
  --build-arg VERSION="$(tr -d '[:space:]' VERSION)" \
  -t loom:local .
```

The repository does not publish a default container image. Use an organization
registry and signing policy when distributing the image.

## GitHub release workflow

Pushing a tag matching `v*` runs the release workflow. It builds Linux, macOS,
and Windows binaries for amd64 and arm64, creates a CycloneDX SBOM, and attaches
the assets to a GitHub release. The installer in `scripts/install.sh` downloads
an exact asset for supported Linux and macOS hosts.

The workflow does not publish Python, npm, or Rust packages. Those SDKs are
installed from a checkout until package publication is added deliberately.

## Security gates

The security workflows are merge and release gates:

- `govulncheck` fails on findings or scan errors;
- `gosec`, CodeQL, secret scanning, and dependency review are blocking;
- the release SBOM is generated with every tagged release; and
- Trivy blocks fixed HIGH and CRITICAL container findings on pull requests,
  main-branch changes, version tags, Docker/dependency changes, and the weekly
  scheduled scan.

Unfixed Trivy findings are still visible but are not treated as a release gate
until a fix exists. Review the scan output and track the exception rather than
silently suppressing it.

Before publishing a container from an organization registry, require the
tagged container-scan workflow to pass for the exact commit and image build
inputs. The repository does not publish a default image itself.

Performance and failure-injection evidence is recorded in
[`PERFORMANCE.md`](PERFORMANCE.md) and [`FAILURE-INJECTION.md`](FAILURE-INJECTION.md).

## Build metadata

The CLI accepts link-time values for version, commit, and build date. A normal
development build uses the root `VERSION` value for its default version and
reports `unknown` for metadata that was not supplied by the build pipeline.
