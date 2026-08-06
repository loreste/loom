package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
)

func TestEmitAddsComplianceCorrelationAndRedactsPayloads(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewLogger(audit.NewWriterSink(&buf))

	event := audit.Event{
		ExecutionID:      "exec-123",
		TraceID:          "trace-123",
		Decision:         core.DecisionAllow.String(),
		Operation:        "payment.capture",
		OperationVersion: "2026-01-01",
		Input: map[string]any{
			"payment_id":     "pay-123",
			"approval_token": "approval-secret",
		},
		Metadata: map[string]string{
			"adapter":       "http",
			"authorization": "Bearer secret-token",
		},
	}

	id, err := logger.Emit(context.Background(), event)
	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}
	if id == "" {
		t.Fatal("Emit() returned an empty audit ID")
	}

	var got audit.Event
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	if got.SchemaVersion != 1 || got.EventType != "execution.decision" {
		t.Fatalf("compliance defaults = schema %d type %q", got.SchemaVersion, got.EventType)
	}
	if got.ProtocolVersion != core.ProtocolVersion {
		t.Fatalf("protocol version = %q, want %q", got.ProtocolVersion, core.ProtocolVersion)
	}
	if got.Adapter != "http" || got.ExecutionID != "exec-123" || got.TraceID != "trace-123" {
		t.Fatalf("correlation fields not preserved: %+v", got)
	}
	if got.InputDigest == "" {
		t.Fatal("input digest is empty")
	}
	if strings.Contains(buf.String(), "approval-secret") || strings.Contains(buf.String(), "secret-token") {
		t.Fatalf("audit event leaked secret: %s", buf.String())
	}
}

func TestDigestRedactsNestedSecrets(t *testing.T) {
	withSecret := audit.Digest(map[string]any{
		"name":   "alice",
		"nested": map[string]any{"password": "one"},
	})
	withoutSecret := audit.Digest(map[string]any{
		"name":   "alice",
		"nested": map[string]any{"password": "two"},
	})
	if withSecret != withoutSecret {
		t.Fatal("secret values changed the digest; redacted digests must be stable")
	}
}

func TestMemorySinkProtectsEventDataFromAliasing(t *testing.T) {
	sink := &audit.MemorySink{}
	event := audit.Event{
		Effects:  []string{"write"},
		Input:    map[string]any{"nested": map[string]any{"value": "original"}},
		Metadata: map[string]string{"adapter": "http"},
	}
	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	snapshot := sink.Snapshot()
	snapshot[0].Effects[0] = "admin"
	snapshot[0].Input["nested"].(map[string]any)["value"] = "changed"
	snapshot[0].Metadata["adapter"] = "cli"

	unchanged := sink.Snapshot()[0]
	if unchanged.Effects[0] != "write" || unchanged.Input["nested"].(map[string]any)["value"] != "original" || unchanged.Metadata["adapter"] != "http" {
		t.Fatalf("memory sink state was aliased: %+v", unchanged)
	}
}
