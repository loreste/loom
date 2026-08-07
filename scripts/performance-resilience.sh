#!/bin/sh
set -eu

# This runner deliberately requires externally managed PostgreSQL and Redis.
# It never substitutes in-memory fakes for durable performance evidence.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=${LOOM_PERF_OUTPUT:-"$root/perf-results-resilience"}
mkdir -p "$out"

if [ -z "${LOOM_DATABASE_URL:-}" ]; then
	echo "LOOM_DATABASE_URL is required for resilience evidence" >&2
	exit 2
fi
if [ -z "${LOOM_REDIS_URL:-}" ]; then
	echo "LOOM_REDIS_URL is required for resilience evidence" >&2
	exit 2
fi

{
	echo "loom_resilience_schema=1"
	echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "go=$(go version)"
	echo "host=$(uname -a)"
	echo "commit=$(git -C "$root" rev-parse HEAD)"
	echo "replicas=${LOOM_PERF_REPLICAS:-1,10,50}"
	echo "soak_duration=${LOOM_PERF_SOAK_DURATION:-24h}"
} > "$out/metadata.txt"

# Integration tests exercise shared PostgreSQL execution/audit state and real
# Redis atomic quota state. The caller supplies restart, failover, latency,
# partition, replica, and soak orchestration around this runner.
go test ./store/postgres -run 'Postgres|Recovery|AuditExport' -count=1 > "$out/postgres-integration.txt"
go test ./quotas -run 'RedisLimiterIntegration' -count=1 > "$out/redis-integration.txt"

LOOM_PERF_OUTPUT="$out/adapters" sh "$root/scripts/performance.sh"
echo "resilience evidence inputs and raw results written to $out"
