package idempotency_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/idempotency"
)

func storedWithOutput() *idempotency.Stored {
	return &idempotency.Stored{
		Fingerprint: "fp",
		Response: core.Response{
			Allowed:  true,
			Decision: core.DecisionAllow,
			Output: map[string]any{
				"id":     "doc-1",
				"nested": map[string]any{"k": "v"},
			},
		},
		StoredAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// Caller mutation of a Completed response must not corrupt the stored replay,
// and mutation of a retrieved replay must not corrupt subsequent retrievals.
func testOutputAliasing(t *testing.T, s idempotency.Store) {
	t.Helper()
	ctx := context.Background()
	st := storedWithOutput()
	if err := s.Begin(ctx, "k1", "fp", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, "k1", st); err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's copy after Complete.
	st.Response.Output["id"] = "hacked"
	st.Response.Output["injected"] = true
	st.Response.Output["nested"].(map[string]any)["k"] = "hacked"

	got, ok, err := s.Get(ctx, "k1")
	if err != nil || !ok {
		t.Fatalf("get: err=%v ok=%v", err, ok)
	}
	if got.Response.Output["id"] != "doc-1" {
		t.Fatalf("stored replay corrupted by post-Complete mutation: %v", got.Response.Output)
	}
	if _, injected := got.Response.Output["injected"]; injected {
		t.Fatal("caller-injected key appeared in stored replay")
	}
	if got.Response.Output["nested"].(map[string]any)["k"] != "v" {
		t.Fatal("nested map aliased with caller memory")
	}

	// Mutating the retrieved replay must not corrupt the next retrieval.
	got.Response.Output["id"] = "rehacked"
	got2, ok, err := s.Get(ctx, "k1")
	if err != nil || !ok {
		t.Fatalf("get2: err=%v ok=%v", err, ok)
	}
	if got2.Response.Output["id"] != "doc-1" {
		t.Fatalf("stored replay corrupted by retrieved-value mutation: %v", got2.Response.Output)
	}
}

func TestMemoryStoreOutputNotAliased(t *testing.T) {
	testOutputAliasing(t, idempotency.NewMemoryStore())
}

func TestFileStoreOutputNotAliased(t *testing.T) {
	fs, err := idempotency.NewFileStore(filepath.Join(t.TempDir(), "idem.json"))
	if err != nil {
		t.Fatal(err)
	}
	testOutputAliasing(t, fs)
}
