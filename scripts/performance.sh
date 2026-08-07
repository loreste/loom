#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=${LOOM_PERF_OUTPUT:-"$root/perf-results"}
count=${LOOM_PERF_COUNT:-5}
time=${LOOM_PERF_TIME:-2s}
mkdir -p "$out"

{
	echo "loom_performance_schema=1"
	echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "go=$(go version)"
	echo "host=$(uname -a)"
	echo "count=$count"
	echo "time=$time"
	echo "database_configured=$([ -n "${LOOM_DATABASE_URL:-}" ] && echo true || echo false)"
	echo "redis_configured=$([ -n "${LOOM_REDIS_URL:-}" ] && echo true || echo false)"
} > "$out/metadata.txt"

go test -run '^$' -bench 'BenchmarkExecuteGranted$' -benchmem -count="$count" -benchtime="$time" ./runtime/ > "$out/in-process.txt"
go test -run '^$' -bench 'BenchmarkExecuteHTTP$' -benchmem -count="$count" -benchtime="$time" ./adapters/http/ > "$out/http-adapter.txt"

echo "performance results written to $out"
echo "Only in-process and HTTP in-memory benchmarks are available in this repository."
echo "Set backend-specific harnesses in the deployment environment before publishing durable results."
