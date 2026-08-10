# Kubernetes deployment

The repository includes a Helm chart at
[`deploy/helm/loom`](../deploy/helm/loom). It deploys the API, the official
recovery worker, and (when configured) a durable webhook delivery worker as
separate workloads. It runs the idempotent PostgreSQL migration hook, configures
health/readiness probes, uses a non-root read-only filesystem, creates no RBAC
permissions, and includes a PDB and NetworkPolicy.

The chart deliberately does not create a database, Redis instance, or runtime
Secret. Supply an externally managed Secret and reference it in values:

```yaml
secrets:
  existingSecret: loom-runtime
recoveryWorker:
  verifierURL: https://provider.example/recovery/verify
```

The Secret must contain keys matching `secrets.*Key` in `values.yaml`:

- `database-url` — PostgreSQL URL for shared durable state;
- `redis-url` — Redis URL for shared fail-closed quotas;
- `jwt-secret` — application JWT signing secret;
- `jwt-issuer` and `jwt-audience` — exact JWT validation values;
- `recovery-verifier-token` — token for the provider verification endpoint; and
- `webhook-secret` — HMAC secret when `loom.webhook.url` is set.

### Audit webhooks

When `loom.webhook.url` is set:

- the API enqueues to `loom_webhook_outbox` (`LOOM_WEBHOOK_DURABLE=true`);
- `webhookWorker` runs `loom webhook-worker` as a separate Deployment;
- `loom.webhook.runWorkerInAPI` stays `false` for multi-replica safety.

```yaml
loom:
  webhook:
    url: https://hooks.example.com/loom
    allowHosts: hooks.example.com
    durable: true
    runWorkerInAPI: false
webhookWorker:
  enabled: true
  replicas: 1
```

Create the Secret through the deployment's secret manager integration, not a
checked-in Kubernetes manifest. The worker sends only execution ID, operation,
and operation version to the verifier. It never sends Loom input, output,
credentials, or approval tokens.

## Install

```sh
helm lint deploy/helm/loom
helm upgrade --install loom deploy/helm/loom \
  --namespace loom --create-namespace \
  --set secrets.existingSecret=loom-runtime \
  --set recoveryWorker.verifierURL=https://provider.example/recovery/verify
```

Put TLS termination and authentication in the ingress or service mesh. The
default chart sets `LOOM_TRUSTED_TLS_PROXY=true`; keep that setting only when
the proxy is actually enforcing TLS and forwarding the original identity
context according to the deployment contract.

## Database, Redis, and upgrades

Use a supported PostgreSQL service with backups, replication, RLS where shared
tenant tables are used, and connection limits. Use a highly available Redis
deployment for quotas. The migration hook runs before install/upgrade; take a
database backup and rehearse forward migration and rollback/fail-forward before
production rollout. Do not roll back application code across a migration until
the compatibility contract says the schema is safe for both versions.

Set the image by immutable digest for production promotion:

```yaml
image:
  repository: ghcr.io/loreste/loom
  digest: sha256:<reviewed-digest>
```

Verify the GHCR image signature and provenance before allowing it into the
cluster. Helm values contain deployment references, not secrets or credentials.
