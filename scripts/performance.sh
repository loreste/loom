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

run_benchmark() {
	name=$1
	package=$2
	pattern=$3
	go test -run '^$' -bench "$pattern" -benchmem -count="$count" -benchtime="$time" "$package" > "$out/$name.txt"
}

run_benchmark in-process ./runtime/ 'BenchmarkExecuteGranted$'
run_benchmark http-adapter ./adapters/http/ 'BenchmarkExecuteHTTP$'
run_benchmark mcp-adapter ./adapters/mcp/ 'BenchmarkCall$'
run_benchmark graphql-adapter ./adapters/graphql/ 'BenchmarkExecuteHTTP$'
run_benchmark grpc-adapter ./adapters/grpc/ 'BenchmarkExecute$'
run_benchmark weft-adapter ./adapters/weft/ 'BenchmarkInvoke$'

echo "performance results written to $out"
echo "These repository benchmarks cover in-process adapters with in-memory dependencies."
echo "Attach deployment-specific PostgreSQL, Redis, identity-provider, replica, and soak results"
echo "before making production capacity claims."
