import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Client } from "../dist/index.js";

const fixture = JSON.parse(readFileSync(fileURLToPath(new URL("../../../conformance/fixtures/execute-semantics.v1.json", import.meta.url)), "utf8"));
assert.equal(fixture.schema_version, 1);
assert.equal(fixture.cases.length, 2);
assert.ok(fixture.cases.every((testCase) => testCase.expected.allowed === false));

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
