package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loreste/loom/audit"
)

// Documented invariant: secrets never appear in audit raw records.
const (
	testAPIKey = "sk-0123456789abcdefghijABCDEF" // matches secret-value pattern
	testPass   = "password=hunter2"
	testBearer = "Bearer tok-super-secret-value"
)

func secretLeakEvent() audit.Event {
	return audit.Event{
		Decision:  "allow",
		Operation: "document.read",
		Message:   "used key " + testAPIKey + " with " + testPass,
		Input: map[string]any{
			"api_key": testAPIKey,
			"note":    testPass,
			"nested":  map[string]any{"token": testAPIKey},
			"safe":    "doc-1",
		},
		Metadata: map[string]string{
			"Authorization": testBearer,
			"X-API-Key":     testAPIKey,
			"TOKEN":         testBearer,
			"safe":          "ok",
		},
	}
}

func assertNoSecrets(t *testing.T, raw string) {
	t.Helper()
	for _, s := range []string{testAPIKey, testPass, "hunter2", testBearer, "tok-super-secret-value"} {
		if strings.Contains(raw, s) {
			t.Fatalf("secret %q leaked into audit record: %s", s, raw)
		}
	}
}

func TestEmitRedactsSecretsMemorySink(t *testing.T) {
	sink := &audit.MemorySink{}
	log := audit.NewLogger(sink)
	id, err := log.Emit(context.Background(), secretLeakEvent())
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("emit should assign an event ID")
	}
	evs := sink.Snapshot()
	if len(evs) != 1 {
		t.Fatalf("events %d", len(evs))
	}
	raw, err := json.Marshal(evs[0])
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, string(raw))
	// non-sensitive data must survive redaction
	if evs[0].Metadata["safe"] != "ok" {
		t.Fatalf("safe metadata lost: %+v", evs[0].Metadata)
	}
	if evs[0].Input["safe"] != "doc-1" {
		t.Fatalf("safe input lost: %+v", evs[0].Input)
	}
}

func TestEmitRedactsSecretsWriterSink(t *testing.T) {
	var buf bytes.Buffer
	log := audit.NewLogger(audit.NewWriterSink(&buf))
	if _, err := log.Emit(context.Background(), secretLeakEvent()); err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, buf.String())
	if !strings.Contains(buf.String(), "[REDACTED]") {
		t.Fatalf("expected redaction markers in raw output: %s", buf.String())
	}
}
