#!/usr/bin/env bash
# End-to-end Loom demo against a running server (or in-process via go run exec).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export LOOM_DATA_DIR="${LOOM_DATA_DIR:-$ROOT/.loom-data}"
mkdir -p "$LOOM_DATA_DIR"

: "${LOOM_DEMO_TOKEN_ALICE:?Set LOOM_DEMO_TOKEN_ALICE for the local demo}"
: "${LOOM_DEMO_TOKEN_BOB:?Set LOOM_DEMO_TOKEN_BOB for the local demo}"
: "${LOOM_DEMO_TOKEN_APPROVER:?Set LOOM_DEMO_TOKEN_APPROVER for the local demo}"
: "${LOOM_DEMO_APPROVAL_TOKEN:?Set LOOM_DEMO_APPROVAL_TOKEN for the local demo}"

echo "==> catalog.spec (alice — agent tool discovery)"
LOOM_TOKEN="$LOOM_DEMO_TOKEN_ALICE" go run ./cmd/loom exec catalog.spec \
  --boundary=dev \
  --input='{}' | head -40

echo "==> document.read (alice)"
LOOM_TOKEN="$LOOM_DEMO_TOKEN_ALICE" go run ./cmd/loom exec document.read \
  --boundary=dev \
  --resource-type=document --resource-id=demo-1 \
  --input='{"id":"demo-1"}' | head -20

echo "==> approval.issue (approver → bob / payment.capture)"
LOOM_TOKEN="$LOOM_DEMO_TOKEN_APPROVER" go run ./cmd/loom exec approval.issue \
  --boundary=dev \
  --idempotency-key="iss-demo-$(date +%s)" \
  --input="{\"principal\":\"user:bob\",\"operation\":\"payment.capture\",\"boundary\":\"dev\",\"token\":\"$LOOM_DEMO_APPROVAL_TOKEN\",\"ttl_seconds\":3600}"

echo "==> payment.capture (bob + approval)"
LOOM_TOKEN="$LOOM_DEMO_TOKEN_BOB" go run ./cmd/loom exec payment.capture \
  --boundary=dev \
  --resource-type=payment --resource-id=demo-pay \
  --idempotency-key="pay-demo-$(date +%s)" \
  --approval="$LOOM_DEMO_APPROVAL_TOKEN" \
  --input='{"amount":25.5,"currency":"USD","merchant_id":"m-demo"}'

echo "==> alice cannot payment.capture (expect deny)"
LOOM_TOKEN="$LOOM_DEMO_TOKEN_ALICE" go run ./cmd/loom exec payment.capture \
  --boundary=dev \
  --resource-type=payment --resource-id=x \
  --idempotency-key=x --approval=y \
  --input='{"amount":1,"currency":"USD","merchant_id":"m"}' || true

echo "==> data dir contents"
ls -la "$LOOM_DATA_DIR"
echo "demo ok"
