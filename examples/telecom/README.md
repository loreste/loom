# Telecom provisioning reference

Run the local reference:

```sh
LOOM_TELECOM_TOKEN="$(openssl rand -hex 24)" go run ./examples/telecom/
```

The example registers exact version `1` operations for creating and modifying
SIP trunks, assigning DIDs, changing routing, and changing customer credit.
Credit changes and other high-risk mutations require an approval token that is
scoped to the operator, tenant boundary, operation, and risk level, then
consumed before the handler runs. A wrong tenant, unknown operation version,
missing approval, or approval replay is denied.

The handler is a provider-shaped simulation. A production deployment must
replace it with a governed provider client, use PostgreSQL RLS and durable
execution/approval/idempotency/audit stores, shared Redis quotas, a verified
OIDC service identity, and a recovery verifier that reconciles provider state
without rerunning the provisioning handler.
