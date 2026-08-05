import assert from "node:assert/strict";
import { Client } from "../dist/index.js";

const contractURL = process.env.LOOM_CONTRACT_URL;
if (contractURL) {
  const client = new Client(contractURL, process.env.LOOM_CONTRACT_TOKEN ?? "");
  const response = await client.call({
    operation: process.env.LOOM_CONTRACT_OPERATION,
    boundary: process.env.LOOM_CONTRACT_BOUNDARY,
    input: {},
  });
  assert.equal(response.Allowed, true, JSON.stringify(response));
  assert.equal(response.Output?.status, "ok");
} else {
  // The package remains testable without a service. Contract execution is
  // opt-in for CI environments that start the shared Loom server.
  const client = new Client("http://example.invalid", "");
  assert.ok(client);
}
