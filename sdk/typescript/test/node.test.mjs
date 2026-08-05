import assert from "node:assert/strict";
import { NodeClient } from "../dist/node.js";

const calls = [];
const fetchImpl = async (_url, init) => {
  calls.push(JSON.parse(init.body));
  return new Response(JSON.stringify({
    Allowed: true,
    Decision: "allow",
    Outcome: "allowed",
    ExecutionID: "exec-node-test",
    Output: { status: "ok" },
  }), { status: 200, headers: { "content-type": "application/json" } });
};

const client = new NodeClient("http://loom.test", "node-token", { fetchImpl });
const response = await client.call({
  operation: "node.health",
  operationVersion: "2",
  boundary: "dev",
  input: {},
});
assert.equal(response.Allowed, true);
assert.equal(response.ExecutionID, "exec-node-test");
assert.equal(calls[0].operation_version, "2");
