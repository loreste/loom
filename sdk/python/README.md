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
```
