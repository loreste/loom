# Loom Python SDK

Thin HTTP client for the Loom Universal Runtime. **All authorization happens server-side.**

```python
from loom import Client, ResourceRef

c = Client(base_url="http://127.0.0.1:8080", token="alice-secret-token")
resp = c.call(
    "document.read",
    boundary="dev",
    resource=ResourceRef(type="document", id="1"),
    input={"id": "1"},
)
assert resp.allowed
print(resp.output)

# Agent discovery (server-enforced)
print(c.manifest())                 # GET /.well-known/loom.json
print(c.openapi())                   # capability-filtered OpenAPI
specs = c.catalog_spec(boundary="dev")
if not resp.allowed and resp.denial:
    print(resp.denial.hint, resp.denial.retryable)
```
