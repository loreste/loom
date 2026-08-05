# Loom TypeScript SDK

## Install from a checkout

```bash
cd sdk/typescript
npm install
npm run build
```

The client talks to a running Loom HTTP adapter; authorization remains
server-side. See [`../../docs/INSTALL.md`](../../docs/INSTALL.md).

```ts
import { Client } from "@loreste/loom-sdk";

const c = new Client("http://127.0.0.1:8080", "alice-secret-token");
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
