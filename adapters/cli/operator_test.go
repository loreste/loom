package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/bootstrap"
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
	if got := a.runAuditExport(context.Background(), []string{"--input=" + path, "--from=1", "--to=2"}); got != 0 {
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
	path := writeAuditFile(t)
	a := New(nil)
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	if got := a.runAuditHead([]string{"--input=" + path}); got != 0 {
		t.Fatalf("runAuditHead() = %d, stderr=%s", got, a.Err.(*bytes.Buffer).String())
	}

	oldKey := strings.Repeat("ab", 32)
	newKey := strings.Repeat("cd", 32)
	checkpointPath := writeCheckpoint(t, path, oldKey)

	// Rotation re-signs with the new key only after the prior checkpoint
	// verifies under the retired one.
	t.Setenv(previousCheckpointKeyEnv, oldKey)
	t.Setenv(checkpointKeyEnv, newKey)
	out := new(bytes.Buffer)
	a.Out, a.Err = out, new(bytes.Buffer)
	if got := a.runAuditRotate([]string{"--input=" + path, "--checkpoint=" + checkpointPath}); got != 0 {
		t.Fatalf("runAuditRotate() = %d, stderr=%s", got, a.Err.(*bytes.Buffer).String())
	}
	var rotated struct {
		Checkpoint audit.Checkpoint `json:"checkpoint"`
	}
	if err := json.Unmarshal(out.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Checkpoint.Signature == "" {
		t.Fatal("rotated checkpoint carries no signature")
	}

	// The rotated checkpoint must verify under the new key and not the old.
	rotatedPath := filepath.Join(t.TempDir(), "rotated.json")
	encodedCheckpoint, err := json.Marshal(rotated.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rotatedPath, encodedCheckpoint, 0o600); err != nil {
		t.Fatal(err)
	}
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	if got := a.runAuditVerifyCheckpoint([]string{"--input=" + path, "--checkpoint=" + rotatedPath}); got != 0 {
		t.Fatalf("verify under the new key = %d, stderr=%s", got, a.Err.(*bytes.Buffer).String())
	}
	t.Setenv(checkpointKeyEnv, oldKey)
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	if got := a.runAuditVerifyCheckpoint([]string{"--input=" + path, "--checkpoint=" + rotatedPath}); got == 0 {
		t.Fatal("rotated checkpoint verified under the retired key")
	}
}

// Rotation must refuse to mint an attestation over a chain the retired key
// never covered; otherwise the new key could vouch for tampered history.
func TestAuditRotateRejectsCheckpointNotSignedByRetiredKey(t *testing.T) {
	path := writeAuditFile(t)
	checkpointPath := writeCheckpoint(t, path, strings.Repeat("ef", 32))
	t.Setenv(previousCheckpointKeyEnv, strings.Repeat("ab", 32)) // wrong retired key
	t.Setenv(checkpointKeyEnv, strings.Repeat("cd", 32))
	a := New(nil)
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	if got := a.runAuditRotate([]string{"--input=" + path, "--checkpoint=" + checkpointPath}); got == 0 {
		t.Fatal("rotate accepted a checkpoint the retired key did not sign")
	}
}

func TestAuditVerifyCheckpointDetectsModifiedChain(t *testing.T) {
	path := writeAuditFile(t)
	key := strings.Repeat("ab", 32)
	checkpointPath := writeCheckpoint(t, path, key)
	t.Setenv(checkpointKeyEnv, key)
	a := New(nil)
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	if got := a.runAuditVerifyCheckpoint([]string{"--input=" + path, "--checkpoint=" + checkpointPath}); got != 0 {
		t.Fatalf("verify of an intact chain = %d, stderr=%s", got, a.Err.(*bytes.Buffer).String())
	}

	// Append an extra event: the chain still hashes, but the checkpoint no
	// longer describes it.
	var extra bytes.Buffer
	chain := audit.NewHashChainSink(audit.NewWriterSink(&extra), "")
	for _, id := range []string{"one", "two"} {
		if err := chain.Write(context.Background(), audit.Event{ID: id, EventType: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, extra.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	if got := a.runAuditVerifyCheckpoint([]string{"--input=" + path, "--checkpoint=" + checkpointPath}); got == 0 {
		t.Fatal("checkpoint verified against a chain it does not attest")
	}
}

func writeAuditFile(t *testing.T) string {
	t.Helper()
	var encoded bytes.Buffer
	chain := audit.NewHashChainSink(audit.NewWriterSink(&encoded), "")
	if err := chain.Write(context.Background(), audit.Event{ID: "one", EventType: "test"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCheckpoint(t *testing.T, auditPath, key string) string {
	t.Helper()
	t.Setenv(checkpointKeyEnv, key)
	a := New(nil)
	out := new(bytes.Buffer)
	a.Out, a.Err = out, new(bytes.Buffer)
	if got := a.runAuditCheckpoint([]string{"--input=" + auditPath}); got != 0 {
		t.Fatalf("runAuditCheckpoint() = %d, stderr=%s", got, a.Err.(*bytes.Buffer).String())
	}
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeStreamExporter stands in for the PostgreSQL audit sink so the CLI's
// durable-stream path is exercised without a database.
type fakeStreamExporter struct {
	events []audit.Event
	gotID  string
	from   int64
	to     int64
	hash   string
	err    error
}

func (f *fakeStreamExporter) ExportStream(_ context.Context, streamID string, from, to int64, trustedPreviousHash string) ([]audit.Event, error) {
	f.gotID, f.from, f.to, f.hash = streamID, from, to, trustedPreviousHash
	if f.err != nil {
		return nil, f.err
	}
	return f.events, nil
}

func TestAuditExportStreamUsesDurableStore(t *testing.T) {
	exporter := &fakeStreamExporter{events: []audit.Event{
		{ID: "one", EventType: "test", Sequence: 7},
		{ID: "two", EventType: "test", Sequence: 8},
	}}
	a := New(nil)
	a.Platform = &bootstrap.Platform{AuditExport: exporter}
	out := new(bytes.Buffer)
	a.Out, a.Err = out, new(bytes.Buffer)
	code := a.runAuditExport(context.Background(), []string{
		"--stream=ops", "--from=7", "--to=8", "--initial-hash=trusted-head",
	})
	if code != 0 {
		t.Fatalf("runAuditExport() = %d, stderr=%s", code, a.Err.(*bytes.Buffer).String())
	}
	if exporter.gotID != "ops" || exporter.from != 7 || exporter.to != 8 || exporter.hash != "trusted-head" {
		t.Fatalf("exporter received %q [%d,%d] hash=%q", exporter.gotID, exporter.from, exporter.to, exporter.hash)
	}
	if strings.Count(out.String(), `"event_type":"test"`) != 2 {
		t.Fatalf("export output = %q", out.String())
	}
}

func TestAuditExportStreamRequiresBoundedRangeAndStore(t *testing.T) {
	a := New(nil)
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	// No durable store configured.
	if got := a.runAuditExport(context.Background(), []string{"--stream=ops", "--from=1", "--to=2"}); got == 0 {
		t.Fatal("stream export succeeded without a durable store")
	}

	a.Platform = &bootstrap.Platform{AuditExport: &fakeStreamExporter{}}
	a.Out, a.Err = new(bytes.Buffer), new(bytes.Buffer)
	// An unbounded range would bypass the store's contiguity guarantee.
	if got := a.runAuditExport(context.Background(), []string{"--stream=ops"}); got == 0 {
		t.Fatal("stream export accepted an unbounded range")
	}
}

func TestAuditExportStreamFailsClosedOnStoreError(t *testing.T) {
	exporter := &fakeStreamExporter{err: errors.New("sequence gap or reordering at 8")}
	a := New(nil)
	a.Platform = &bootstrap.Platform{AuditExport: exporter}
	out := new(bytes.Buffer)
	a.Out, a.Err = out, new(bytes.Buffer)
	if got := a.runAuditExport(context.Background(), []string{"--stream=ops", "--from=7", "--to=8"}); got == 0 {
		t.Fatal("stream export succeeded despite a store error")
	}
	if out.Len() != 0 {
		t.Fatalf("failed export wrote %q to stdout", out.String())
	}
}
