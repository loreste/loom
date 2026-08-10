# Loom Python SDK

This is a thin HTTP client for the Loom runtime. Authorization remains
server-side; the SDK cannot grant permissions.

- **Distribution name (PyPI):** `loreste-loom`
- **Import package:** `loom`
- **Do not use** PyPI `loom-sdk` — that name is owned by an unrelated project.

Registry publication is pending trusted-publisher configuration. Install from
this checkout until [`docs/RELEASES.md`](../../docs/RELEASES.md) marks the
package published:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./sdk/python
# future public install: python -m pip install loreste-loom
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
