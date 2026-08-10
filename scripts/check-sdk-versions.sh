#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
expected=${1:-$(tr -d '\r\n' < "$root/VERSION")}
expected=${expected#v}

read_value() {
	file=$1
	pattern=$2
	value=$(sed -E -n "s/$pattern/\\1/p" "$file" | head -n 1)
	if [ -z "$value" ]; then
		echo "version not found in $file" >&2
		exit 1
	fi
	printf '%s' "$value"
}

python_version=$(read_value "$root/sdk/python/pyproject.toml" '^version = "([^"]+)"$')
python_name=$(read_value "$root/sdk/python/pyproject.toml" '^name = "([^"]+)"$')
typescript_version=$(read_value "$root/sdk/typescript/package.json" '^[[:space:]]*"version": "([^"]+)",$')
rust_version=$(read_value "$root/sdk/rust/Cargo.toml" '^version = "([^"]+)"$')
python_agent_version=$(read_value "$root/sdk/python/loom/__init__.py" '^[[:space:]]*user_agent: str = "loom-python-sdk\/([^"]+)"')
typescript_agent_version=$(read_value "$root/sdk/typescript/src/index.ts" '^[[:space:]]*"User-Agent": "loom-typescript-sdk\/([^",]+)",[[:space:]]*$')
rust_agent_version=$(read_value "$root/sdk/rust/src/lib.rs" '^[[:space:]]*\.header\(USER_AGENT, "loom-rust-sdk\/([^" )]+)"\)[[:space:]]*$')

if [ "$python_name" = "loom-sdk" ]; then
	echo "Python distribution name must not be the conflicting PyPI name loom-sdk; use loreste-loom" >&2
	exit 1
fi
if [ "$python_name" != "loreste-loom" ]; then
	echo "Python distribution name $python_name does not match expected loreste-loom" >&2
	exit 1
fi

for pair in \
  "Python:$python_version" \
  "TypeScript:$typescript_version" \
  "Rust:$rust_version" \
  "Python user agent:$python_agent_version" \
  "TypeScript user agent:$typescript_agent_version" \
  "Rust user agent:$rust_agent_version"; do
	name=${pair%%:*}
	value=${pair#*:}
	if [ "$value" != "$expected" ]; then
		echo "$name SDK version $value does not match release version $expected" >&2
		exit 1
	fi
done

echo "SDK versions match $expected (python distribution=$python_name)"
