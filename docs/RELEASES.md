# Release and publication model

Loom uses the root [`VERSION`](../VERSION) file as the source of truth for
the Go CLI and all supported SDK packages. A release tag is the same version
with a `v` prefix, for example `VERSION=X.Y.Z` and tag `vX.Y.Z`.

## Published artifacts

- immutable Go binaries for supported operating systems and architectures;
- SHA-256 checksums, keyless signatures, SBOM, and build provenance;
- a signed multi-architecture image at `ghcr.io/<owner>/<repository>`; and
- the GitHub release's package of checksums, signatures, SBOM, and provenance.

For v1.0.0, the Go module, binaries, image, checksums, signatures, SBOM, and
provenance evidence are available from the GitHub release and GHCR. The
machine-readable inventory is [`release-manifest.json`](../release-manifest.json).

**Python, TypeScript/npm, and Rust SDKs are not published to public registries
for v1.0.0.** The v1 tag's SDK publication workflow failed, and automatic
tag-triggered SDK publishing is disabled until trusted-publisher configuration
and conflict-free package identities are confirmed. Install those SDKs from a
repository checkout until an unauthenticated public install of the exact
version succeeds and this document is updated.

Intended registry coordinates (not yet public):

| Language   | Coordinate              | Status                                      |
|------------|-------------------------|---------------------------------------------|
| Go         | `github.com/loreste/loom` | Published via immutable git tags          |
| Python     | PyPI `loreste-loom`     | Pending; never use conflicting `loom-sdk`   |
| TypeScript | npm `@loreste/loom-sdk` | Pending scope ownership and first publish   |
| Rust       | crates.io `loom-sdk`    | Pending ownership confirmation              |

Go consumers use the immutable Git tag through the Go module proxy.

## Trusted publishing configuration

Publication uses GitHub OIDC wherever the registry supports it. Configure
protected environments named `pypi`, `npm`, and `crates-io`, and register this
repository and its release workflow with each registry's trusted-publisher
settings. The npm job uses npm trusted publishing through GitHub OIDC; no
long-lived npm token is stored in GitHub Actions or the repository. The PyPI and
crates.io publishers use the equivalent OIDC configuration at their registries.

The container job uses the repository-scoped `GITHUB_TOKEN` for GHCR and keyless
Cosign identity from GitHub OIDC. No registry credentials are baked into the
image or release artifacts.

Configure the three package registries with these exact trusted-publisher values
before running SDK publication:

- PyPI: owner `loreste`, repository `loom`, workflow `sdk-publish.yml`,
  environment `pypi`.
- npm: owner or organization `loreste`, repository `loom`, workflow
  `sdk-publish.yml`, environment `npm`; do not add a token secret.
- crates.io: GitHub repository `loreste/loom`, workflow `sdk-publish.yml`,
  environment `crates-io`.

The workflow must be allowed to request an OIDC token (`id-token: write`). If a
registry reports `invalid-publisher` or `No Trusted Publishing config found`,
the registry-side publisher has not been registered yet. After registration,
rerun the tag publication workflow with:

    gh workflow run sdk-publish.yml --ref main -f ref=vX.Y.Z

## Release gate

Tag pushes run Go CI, security scanning, dependency review, and container
scanning for the exact tag commit. Binary, SDK, and image publication waits for
those workflows. The
release workflow also supports an explicit manual rerun for an existing tag
after a transient publication failure:

    gh workflow run release.yml --ref main -f ref=vX.Y.Z

A release must be cut from a clean, reviewed commit; exact-commit CI,
security, dependency review, container scan, and SDK contract checks must pass
before publication. When SDK registry publication is re-enabled, the workflow
must install each package unauthenticated from the public registry, verify the
installed version and repository metadata, run conformance fixtures against the
exact server release, and fail if any coordinate differs from
`release-manifest.json`.

## Verify a release offline

Download the binary, `SHA256SUMS`, `.sigstore.json` bundles, SBOM, and provenance
from the GitHub release. Verify the digest before opening the binary:

```sh
sha256sum -c SHA256SUMS
cosign verify-blob --bundle loom-linux-amd64.sigstore.json \
  --certificate-identity-regexp 'https://github.com/loreste/loom/.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  loom-linux-amd64
```

A checksum is an integrity check; it is not a substitute for verifying the
signing identity and provenance.

## Version and deprecation policy

Patch releases preserve the documented compatibility contract. New required
fields, denial codes, or operation-version behavior require a compatibility note
and migration guidance. Breaking changes are reserved for a documented major
release and are not hidden in a patch tag.
