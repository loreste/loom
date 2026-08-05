package audit_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/loreste/loom/audit"
)

func TestEmitRedactsCapitalizedSensitiveMetadata(t *testing.T) {
	sink := &audit.MemorySink{}
	l := audit.NewLogger(sink)
	_, err := l.Emit(context.Background(), audit.Event{
		Operation: "op",
		Metadata: map[string]string{
			"Authorization":    "Bearer abc",
			"X-Approval-Token": "tok123",
			"COOKIE":           "session=1",
			"note":             "harmless",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	md := sink.Snapshot()[0].Metadata
	for _, k := range []string{"Authorization", "X-Approval-Token", "COOKIE"} {
		if md[k] != "[REDACTED]" {
			t.Errorf("metadata key %q not redacted: %q", k, md[k])
		}
	}
	if md["note"] != "harmless" {
		t.Fatalf("harmless metadata over-redacted: %q", md["note"])
	}
}

func TestEmitScrubsSecretInMessage(t *testing.T) {
	sink := &audit.MemorySink{}
	l := audit.NewLogger(sink)
	secret := "sk-abcdefghijklmnopqrstuvwxyz"
	_, err := l.Emit(context.Background(), audit.Event{
		Operation: "op",
		Message:   "handler failed with credential " + secret + " inside",
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := sink.Snapshot()[0].Message
	if strings.Contains(msg, secret) {
		t.Fatalf("secret leaked into audit message: %q", msg)
	}
	if !strings.Contains(msg, "[REDACTED]") {
		t.Fatalf("expected redaction marker in message: %q", msg)
	}
}

func TestEmitScrubsSecretInMetadataValues(t *testing.T) {
	sink := &audit.MemorySink{}
	l := audit.NewLogger(sink)
	secret := "ghp_abcdefghijklmnopqrstuvwxyz"
	_, err := l.Emit(context.Background(), audit.Event{
		Operation: "op",
		Metadata:  map[string]string{"note": "saw " + secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := sink.Snapshot()[0].Metadata["note"]; strings.Contains(got, secret) {
		t.Fatalf("secret leaked into metadata value: %q", got)
	}
}

func TestEmitRedactsNestedCredentialKeys(t *testing.T) {
	sink := &audit.MemorySink{}
	logger := audit.NewLogger(sink)
	if _, err := logger.Emit(context.Background(), audit.Event{
		Input: map[string]any{
			"credentials": map[string]any{
				"password": "hunter2",
				"username": "alice",
			},
		},
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sink.Snapshot()[0].Input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Fatalf("nested credential leaked: %s", raw)
	}
}
