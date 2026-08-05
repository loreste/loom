# Loom TypeScript SDK

```ts
import { Client } from "@loreste/loom-sdk";

const c = new Client("http://127.0.0.1:8080", "alice-secret-token");
const resp = await c.call({
  operation: "document.read",
  boundary: "dev",
  resource: { type: "document", id: "1" },
  input: { id: "1" },
});
if (!resp.Allowed) throw new Error(resp.Denial?.Message);
console.log(resp.Output);
```
