# Loom TypeScript SDK

The TypeScript SDK is a thin HTTP client. Loom remains responsible for
authentication, authorization, guardrails, approvals, quotas, idempotency,
execution, filtering, and audit.

The package version matches the Loom release (`VERSION` in the repository root).
npm publication of `@loreste/loom-sdk` is pending trusted-publisher
configuration—see [`docs/RELEASES.md`](../../docs/RELEASES.md). Install from
this checkout for now:

```bash
cd sdk/typescript
npm install
npm run build
npm test
```

Node.js applications should use the `NodeClient` entry point. It requires Node
18 or a compatible `fetch` implementation:

```ts
import { NodeClient } from "@loreste/loom-sdk/node";

const token = process.env.LOOM_TOKEN;
if (!token) throw new Error("LOOM_TOKEN is required");

const client = new NodeClient("http://127.0.0.1:8080", token);
const response = await client.call({
  operation: "document.read",
  operationVersion: "1",
  boundary: "dev",
  resource: { type: "document", id: "1" },
  input: { id: "1" },
});
if (!response.Allowed) throw new Error(response.Denial?.Hint ?? "denied");
console.log(response.Output);
```

Browser-compatible callers can import `Client` and provide a compatible fetch
implementation. See [`../../docs/INSTALL.md`](../../docs/INSTALL.md) and
[`../../docs/SDK.md`](../../docs/SDK.md).
