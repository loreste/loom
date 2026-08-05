# Build and release

Loom has no required runtime service for embedded use. The Go module, SDK
packages, Docker image, release binaries, and installer are all built from
the repository.

```bash
make test-race
make build
make release LOOM_VERSION=$(tr -d '[:space:]' < VERSION)
docker build --build-arg VERSION=$(tr -d '[:space:]' < VERSION) -t loom:local .
```

`LOOM_VERSION`, `LOOM_COMMIT`, `LOOM_BUILD_DATE`, `DIST_DIR`, and
`VERSION_FILE` are overrideable. Runtime credentials, database URLs, identity
configuration, and tenant policy are never embedded in release artifacts.

The release workflow publishes the cross-platform binaries when a `v*` tag is
created. The installer requires `LOOM_REPOSITORY` (or `GITHUB_REPOSITORY`) and
an exact `LOOM_VERSION`, then installs into `LOOM_INSTALL_DIR` (defaulting to
the user's local bin).
