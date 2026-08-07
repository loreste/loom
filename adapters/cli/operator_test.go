package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loreste/loom/audit"
)

func TestValidateOperatorURL(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		ok   bool
	}{
		{name: "https", url: "https://loom.example", ok: true},
		{name: "local http", url: "http://127.0.0.1:8080", ok: true},
		{name: "remote http", url: "http://loom.example", ok: false},
		{name: "relative", url: "/loom", ok: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validateOperatorURL(test.url) == nil; got != test.ok {
				t.Fatalf("validateOperatorURL(%q) = %v, want %v", test.url, got, test.ok)
			}
		})
	}
}

func TestAuditVerifyCommand(t *testing.T) {
	var encoded bytes.Buffer
	chain := audit.NewHashChainSink(audit.NewWriterSink(&encoded), "")
	if err := chain.Write(context.Background(), audit.Event{ID: "one", EventType: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Write(context.Background(), audit.Event{ID: "two", EventType: "test"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	a := New(nil)
	a.Out = out
	a.Err = errOut
	if got := a.runAuditVerify([]string{"--input=" + path}); got != 0 {
		t.Fatalf("runAuditVerify() = %d, stderr=%s", got, errOut.String())
	}
	if !strings.Contains(out.String(), `"valid":true`) {
		t.Fatalf("verification output = %q", out.String())
	}
}

func TestAuditExportCommandVerifiesAndFilters(t *testing.T) {
	var encoded bytes.Buffer
	chain := audit.NewHashChainSink(audit.NewWriterSink(&encoded), "")
	for i, id := range []string{"one", "two"} {
		if err := chain.Write(context.Background(), audit.Event{ID: id, EventType: "test", Sequence: int64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	a := New(nil)
	a.Out = out
	a.Err = errOut
	if got := a.runAuditExport([]string{"--input=" + path, "--from=1", "--to=2"}); got != 0 {
		t.Fatalf("runAuditExport() = %d, stderr=%s", got, errOut.String())
	}
	if strings.Count(out.String(), "\"event_type\":\"test\"") != 2 {
		t.Fatalf("export output = %q", out.String())
	}
}

func TestAuditCheckpointRequiresEnvironmentKey(t *testing.T) {
	var encoded bytes.Buffer
	chain := audit.NewHashChainSink(audit.NewWriterSink(&encoded), "")
	if err := chain.Write(context.Background(), audit.Event{ID: "one", EventType: "test"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOOM_AUDIT_CHECKPOINT_KEY", strings.Repeat("ab", 32))
	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	a := New(nil)
	a.Out = out
	a.Err = errOut
	if got := a.runAuditCheckpoint([]string{"--input=" + path}); got != 0 {
		t.Fatalf("runAuditCheckpoint() = %d, stderr=%s", got, errOut.String())
	}
	if !strings.Contains(out.String(), `"event_count":1`) || !strings.Contains(out.String(), `"signature"`) {
		t.Fatalf("checkpoint output = %q", out.String())
	}
}

func TestAuditHeadAndRotate(t *testing.T) {
	var encoded bytes.Buffer
	chain := audit.NewHashChainSink(audit.NewWriterSink(&encoded), "")
	if err := chain.Write(context.Background(), audit.Event{ID: "one", EventType: "test"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New(nil)
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	if got := a.runAuditHead([]string{"--input=" + path}); got != 0 {
		t.Fatalf("runAuditHead() = %d, stderr=%s", got, a.Err.(*bytes.Buffer).String())
	}
	t.Setenv("LOOM_AUDIT_CHECKPOINT_KEY", strings.Repeat("ab", 32))
	if got := a.runAuditRotate([]string{"--input=" + path}); got != 0 {
		t.Fatalf("runAuditRotate() = %d, stderr=%s", got, a.Err.(*bytes.Buffer).String())
	}
}
