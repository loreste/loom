package idempotency_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/idempotency"
)

func TestFileStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.json")
	s1, err := idempotency.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	fp := "abc123"
	if err := s1.Begin(context.Background(), "k1", fp, time.Hour); err != nil {
		t.Fatal(err)
	}
	resp := core.Response{Allowed: true, Decision: core.DecisionAllow, TraceID: "t1", Output: map[string]any{"ok": true}}
	if err := s1.Complete(context.Background(), "k1", &idempotency.Stored{
		Fingerprint: fp,
		Response:    resp,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	s2, err := idempotency.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok, err := s2.Get(context.Background(), "k1")
	if err != nil || !ok {
		t.Fatalf("get: %v ok=%v", err, ok)
	}
	if st.Fingerprint != fp || !st.Response.Allowed {
		t.Fatalf("%+v", st)
	}
}

func TestFileStoreConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idem.json")
	s, _ := idempotency.NewFileStore(path)
	_ = s.Begin(context.Background(), "k", "fp1", time.Hour)
	_ = s.Complete(context.Background(), "k", &idempotency.Stored{
		Fingerprint: "fp1",
		Response:    core.Response{Allowed: true},
		ExpiresAt:   time.Now().Add(time.Hour),
	})
	err := s.Begin(context.Background(), "k", "fp2", time.Hour)
	if err == nil {
		t.Fatal("conflict expected")
	}
}
