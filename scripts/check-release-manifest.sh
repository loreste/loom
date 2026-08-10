#!/bin/sh
# Fail closed when public release claims drift from repository reality.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root/release-manifest.json"
version=$(tr -d '\r\n' < "$root/VERSION")

if [ ! -f "$manifest" ]; then
	echo "missing release-manifest.json" >&2
	exit 1
fi

python3 - "$root" "$manifest" "$version" <<'PY'
import json, pathlib, re, sys

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
version = sys.argv[3]
data = json.loads(manifest_path.read_text(encoding="utf-8"))

errors = []

# Python distribution must never be the conflicting loom-sdk name.
pyproject = (root / "sdk/python/pyproject.toml").read_text(encoding="utf-8")
m = re.search(r'^name = "([^"]+)"', pyproject, re.M)
if not m:
    errors.append("python package name not found")
elif m.group(1) == "loom-sdk":
    errors.append("python distribution must not be conflicting name loom-sdk")
elif m.group(1) != "loreste-loom":
    errors.append(f"python distribution {m.group(1)!r} != loreste-loom")

py_sdk = next((s for s in data.get("sdks", []) if s.get("language") == "python"), None)
if not py_sdk:
    errors.append("release-manifest missing python sdk")
else:
    if py_sdk.get("distribution") != "loreste-loom":
        errors.append("manifest python distribution must be loreste-loom")
    if py_sdk.get("blocked_name") != "loom-sdk":
        errors.append("manifest must block loom-sdk")
    if py_sdk.get("published") is True:
        errors.append("manifest must not claim python published until public install succeeds")

for sdk in data.get("sdks", []):
    if sdk.get("language") in ("typescript", "rust") and sdk.get("published") is True:
        errors.append(f"manifest claims {sdk['language']} published without registry gate")

# CLI inventory must match DocumentedCommands source of truth in Go.
commands_go = (root / "adapters/cli/commands.go").read_text(encoding="utf-8")
# Extract top-level list from DocumentedCommands.
block = re.search(
    r'"":\s*\{([^}]+)\}',
    commands_go,
    re.S,
)
if not block:
    errors.append("could not parse DocumentedCommands top-level list")
else:
    go_cmds = re.findall(r'"([^"]+)"', block.group(1))
    manifest_cmds = data.get("cli_commands", {}).get("top_level", [])
    if go_cmds != manifest_cmds:
        errors.append(f"cli top_level mismatch: go={go_cmds} manifest={manifest_cmds}")

# Changelog and RELEASES must not claim SDKs are published.
releases = (root / "docs/RELEASES.md").read_text(encoding="utf-8")
if "The Python, TypeScript, and Rust SDKs are published" in releases:
    errors.append("docs/RELEASES.md still claims SDKs are published")
if "not published to public registries" not in releases and "are not published" not in releases:
    errors.append("docs/RELEASES.md must state SDKs are not published")

changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
for ghost in ("loom operator status", "recovery approve", "recovery reject"):
    # Only flag as current claims if under Unreleased false advertising;
    # historical 1.0.0 section was corrected to requeue/dead-letter.
    pass
if "`loom recovery list`, `approve`, `reject`" in changelog:
    errors.append("CHANGELOG still advertises non-existent recovery approve/reject")
if "loom operator status" in changelog and "no `loom operator` group" not in changelog:
    # Allow if corrected in Unreleased note
    if "no `loom operator`" not in changelog and "no loom operator" not in changelog.lower():
        errors.append("CHANGELOG still advertises loom operator commands without correction")

if errors:
    print("release-manifest checks failed:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print(f"release-manifest checks passed for version {version}")
PY
