# Shared conformance fixtures

`execute-semantics.v1.json` is a language-neutral, versioned fixture for SDK
and adapter contract tests. Consumers must preserve the request fields and
assert only the stable response fields listed under `expected`; denial reason
messages and output formatting are not part of the wire contract.

The fixture intentionally contains deny cases so an SDK or adapter cannot turn
authentication, operation discovery, or missing idempotency into an implicit
grant. Repository adapter tests cover the same governed runtime semantics.
SDK publication/contract jobs should execute this fixture against the public
contract server for each supported language before publication.
