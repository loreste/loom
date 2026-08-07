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
typescript_version=$(read_value "$root/sdk/typescript/package.json" '^[[:space:]]*"version": "([^"]+)",$')
rust_version=$(read_value "$root/sdk/rust/Cargo.toml" '^version = "([^"]+)"$')

for pair in \
	"Python:$python_version" \
	"TypeScript:$typescript_version" \
	"Rust:$rust_version"; do
	name=${pair%%:*}
	value=${pair#*:}
	if [ "$value" != "$expected" ]; then
		echo "$name SDK version $value does not match release version $expected" >&2
		exit 1
	fi
done

echo "SDK versions match $expected"
