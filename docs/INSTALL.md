# Installation

Choose the installation path that matches how Loom will run. Loom is an
embedded Go runtime; it does not require a separate control-plane service.
After installation, use [`CONFIGURATION.md`](CONFIGURATION.md) for the full
environment reference and [`OPERATIONS.md`](OPERATIONS.md) for production
rollout and failure handling.

## Prerequisites

- Go version declared in [`go.mod`](../go.mod) for the CLI and embedded use.
- Docker, only if building the container image.
- Python 3.10 or newer for the Python SDK.
- Node.js 18 or newer for the Node.js SDK.
- Rust stable for the Rust SDK.
- PostgreSQL for shared durable state.
- Redis for distributed quota state.

PostgreSQL and Redis are optional for local development. They become required
when the selected production deployment needs shared durable state or shared
quotas.

## Build the CLI from source

```bash
git clone https://github.com/loreste/loom.git
cd loom
make build
go build -o ./loom ./cmd/loom
./loom version
```

Run an embedded example before exposing a network adapter:

```bash
LOOM_EXAMPLE_TOKEN="$(openssl rand -hex 24)" \
  go run ./examples/orders-app/

LOOM_EXAMPLE_TOKEN="$(openssl rand -hex 24)" \
LOOM_EXAMPLE_APPROVAL_TOKEN="$(openssl rand -hex 24)" \
  go run ./examples/embed/
```

The examples use development-only credentials and in-process storage. They are
not production configurations.

## Install a release binary

The repository publishes Linux, macOS, and Windows binaries for amd64 and
arm64. The installer script supports Linux and macOS. It requires an exact
release tag and does not guess a version:

```bash
export LOOM_REPOSITORY=loreste/loom
export LOOM_VERSION=vX.Y.Z
curl --fail --location \
  "https://raw.githubusercontent.com/${LOOM_REPOSITORY}/${LOOM_VERSION}/scripts/install.sh" \
  | sh

~/.local/bin/loom version
```

Set `LOOM_INSTALL_DIR` to use another destination. The installer downloads the
matching release asset but does not perform signature or checksum verification
itself. For higher-assurance deployments, verify the release asset digest or
use an organization-controlled mirror before installation. Windows users can
download the matching `.exe` asset from the [release page](https://github.com/loreste/loom/releases).

## Build and run the Docker image

The repository builds the image locally; it does not publish a default image
to a container registry.

```bash
docker build \
  --build-arg VERSION="$(tr -d '[:space:]' VERSION)" \
  -t loom:local .

docker run --rm -p 8080:8080 \
  -e LOOM_ENV=development \
  -e LOOM_DEMO_TOKEN_ALICE="loom-dev-$(openssl rand -hex 24)" \
  loom:local
```

For a remote client, set the same value in `LOOM_TOKEN` before starting the
container. The image contains the CLI only; identity, database, Redis, policy,
and secret configuration remain deployment configuration.

## Add Loom to a Go application

Use an exact release tag in the application module:

```bash
go get github.com/loreste/loom@vX.Y.Z
```

Then use `app.New` or `app.Bootstrap`, register operations, grant explicit
policy and resource access, and call only through `app.Call`. See
[`EMBED.md`](EMBED.md) and [`HOWTO.md`](HOWTO.md).

## Install the SDKs from this repository

The Go SDK is part of the Go module. The Python, TypeScript, and Rust SDKs are
included in this repository but are not published to package registries by the
current release workflows.

Python:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./sdk/python
```

TypeScript/Node:

```bash
cd sdk/typescript
npm install
npm run build
npm test
```

For an application outside this checkout, build the SDK in the checkout and
package it through the application's workspace or package process:

```bash
cd /path/to/loom/sdk/typescript
npm install
npm run build
```

The package exports compiled files from `dist/`; `npm install` alone does not
create that directory.

Rust:

```toml
[dependencies]
loom-sdk = { path = "../loom/sdk/rust" }
```

All SDKs call the HTTP adapter and cannot grant themselves permissions. The Go
SDK also supports in-process calls, and the Weft SDK is an in-process Go client.

## Production prerequisites

Do not use demo principals or ephemeral development identity settings in
production. The CLI production profile requires explicit durable state and
identity configuration:

```bash
export LOOM_ENV=production
export LOOM_DISABLE_DEMO_PRINCIPALS=true
export LOOM_REQUIRE_DURABLE=true
export LOOM_DATABASE_URL='postgres://...'
export LOOM_REDIS_URL='redis://...'
export LOOM_JWT_SECRET='<value supplied by your secret manager>'
export LOOM_JWT_KEY_ID='active-key'
export LOOM_JWT_ISSUER='https://issuer.example'
export LOOM_JWT_AUDIENCE='loom-api'
```

The built-in verifier supports configured HMAC JWT verification. OIDC discovery,
JWKS rotation, revocation, and enterprise identity lifecycle remain application
integration responsibilities; see [`IDENTITY.md`](IDENTITY.md).

For a single node, `LOOM_DATA_DIR` provides file-backed approvals, idempotency,
execution status, and audit state. For multiple replicas, set
`LOOM_DATABASE_URL`; the PostgreSQL bundle includes a shared execution-status
and recovery store. Redis is required when quota state must be shared.

If a verified JWT carries a tenant claim, set `LOOM_TENANT_CLAIM` and configure
tenant-aware database access as described in [`TENANCY.md`](TENANCY.md).

## Next steps

- Make a first governed call with [`HOWTO.md`](HOWTO.md).
- Use the HTTP endpoints from [`API.md`](API.md).
- Embed the runtime without a server using [`EMBED.md`](EMBED.md).
- Review the security and identity boundaries in [`SECURITY.md`](SECURITY.md)
  and [`IDENTITY.md`](IDENTITY.md).
