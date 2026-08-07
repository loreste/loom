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
