# Installation

Choose the installation path that matches how Loom will run.

## Prerequisites

- Go version declared in [`go.mod`](../go.mod) for building Loom or embedding the Go module.
- Docker for container builds.
- Python 3.10+, Node.js 18+, or Rust stable for the corresponding SDK.

Loom has no required control-plane service for embedded use. PostgreSQL and
Redis are needed only when the deployment selects durable state or distributed
quotas.

## Build the CLI from source

```bash
git clone https://github.com/loreste/loom.git
cd loom
make build
./loom version
```

Run a local example before exposing a network adapter:

```bash
go run ./examples/embed/
go run ./examples/orders-app/
```

## Install a release binary

The installer downloads an asset from a GitHub release. Set the repository and
exact release tag; it does not guess a version.

```bash
export LOOM_REPOSITORY=loreste/loom
export LOOM_VERSION=v0.1.1
curl --fail --location https://raw.githubusercontent.com/${LOOM_REPOSITORY}/${LOOM_VERSION}/scripts/install.sh | sh
~/.local/bin/loom version
```

Set `LOOM_INSTALL_DIR` to choose another destination. Verify release checksums
and use an organization-controlled mirror when required.

## Build and run Docker

```bash
docker build \
  --build-arg VERSION="$(tr -d '[:space:]' < VERSION)" \
  -t loom:local .
docker run --rm -p 8080:8080 \
  -e LOOM_ENV=development \
  loom:local
```

The image contains the CLI only. Identity, database, Redis, policy, and secret
configuration are supplied at runtime.

## Add Loom to a Go application

```bash
go get github.com/loreste/loom@v0.1.1
```

Use the embed API to register operations, identities, boundaries, policies,
and resource grants. Callers invoke only `app.Call`. See [HOWTO.md](HOWTO.md)
and [EMBED.md](EMBED.md).

## Install SDKs from a checkout

Python:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./sdk/python
```

TypeScript:

```bash
cd sdk/typescript
npm install
npm run build
```

Rust:

```toml
[dependencies]
loom-sdk = { path = "../loom/sdk/rust" }
```

All SDKs call the HTTP adapter and cannot grant themselves additional Loom
permissions.

## Production prerequisites

Do not use demo principals or ephemeral development identity settings in
production. The CLI production profile requires durable state and explicit
identity configuration:

```bash
export LOOM_ENV=production
export LOOM_DISABLE_DEMO_PRINCIPALS=true
export LOOM_REQUIRE_DURABLE=true
export LOOM_DATABASE_URL='postgres://...'
export LOOM_REDIS_URL='redis://...'
export LOOM_JWT_SECRET='managed-secret-at-least-16-bytes'
export LOOM_JWT_KEY_ID='active-key'
export LOOM_JWT_ISSUER='https://issuer.example'
export LOOM_JWT_AUDIENCE='loom-api'
```

See [IDENTITY.md](IDENTITY.md) for OIDC/JWKS and mTLS integration, and
[TENANCY.md](TENANCY.md) plus the [tenant reference](../examples/tenancy/README.md)
for database isolation.
