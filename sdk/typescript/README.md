# Loom TypeScript SDK

The package supports Node 18+ applications and other environments with a
compatible `fetch` implementation. `NodeClient` is the named Node entry point;
it uses the same governed HTTP execution contract as `Client`.

## Install from a checkout

```bash
cd sdk/typescript
npm install
npm run build
npm test
```

Node application:

```ts
import { NodeClient } from "@loreste/loom-sdk/node";

const client = new NodeClient("http://127.0.0.1:8080", process.env.LOOM_TOKEN);
const response = await client.call({
  operation: "document.read",
  operationVersion: "1",
  boundary: "dev",
  input: { id: "1" },
});
if (!response.Allowed) throw new Error(response.Denial?.Hint ?? "denied");
```

The client talks to a running Loom HTTP adapter; authorization remains
server-side. See [`../../docs/INSTALL.md`](../../docs/INSTALL.md).

```ts
import { Client } from "@loreste/loom-sdk";

const token = process.env.LOOM_TOKEN;
if (!token) throw new Error("LOOM_TOKEN is required");
const c = new Client("http://127.0.0.1:8080", token);
const resp = await c.call({
  operation: "document.read",
  boundary: "dev",
  resource: { type: "document", id: "1" },
  input: { id: "1" },
});
if (!resp.Allowed) throw new Error(resp.Denial?.Hint ?? resp.Denial?.Message);
console.log(resp.Output);

// Agent discovery
const manifest = await c.manifest();
const openapi = await c.openapi();
const tools = await c.mcp({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
```
