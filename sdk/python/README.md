# Loom Python SDK

This is a thin HTTP client for the Loom runtime. Authorization remains
server-side; the SDK cannot grant permissions.

The 0.2.1 source is version-aligned with Loom, but its PyPI publication is
pending registry trusted-publisher configuration. Install it from this
checkout for now:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./sdk/python
```

Start a development Loom HTTP adapter and set `LOOM_TOKEN` to the corresponding
development principal token before running the example:

```python
import os

from loom import Client, ResourceRef

client = Client("http://127.0.0.1:8080", token=os.environ["LOOM_TOKEN"])
response = client.call(
    "document.read",
    operation_version="1",
    boundary="dev",
    resource=ResourceRef(type="document", id="1"),
    input={"id": "1"},
)
if not response.allowed:
    raise RuntimeError(response.denial.hint if response.denial else "denied")
print(response.output)
```

See [`../../docs/INSTALL.md`](../../docs/INSTALL.md) and
[`../../docs/SDK.md`](../../docs/SDK.md) for setup, discovery, and reliability
outcomes.
