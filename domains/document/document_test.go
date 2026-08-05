package document_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/domains/document"
)

func setupDocApp(t *testing.T) (*app.App, *document.Store) {
	t.Helper()
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	store := document.NewStore()
	if err := document.Register(a.Registry, store); err != nil {
		t.Fatal(err)
	}
	return a, store
}

func TestDocumentReadWriteRoundTrip(t *testing.T) {
	a, _ := setupDocApp(t)
	_ = a.AddUser("u", "tok", "dev", []string{"document.read", "document.write"})
	_ = a.GrantOp("u", "dev", "document.read", "document", "*", []string{"id", "title", "body"})
	_ = a.GrantOp("u", "dev", "document.write", "document", "*", []string{"id", "title", "status"})

	ctx := context.Background()
	w := a.Call(ctx, core.Request{
		Operation:      "document.write",
		Credentials:    core.Credentials{Token: "tok"},
		Boundary:       "dev",
		Resource:       &core.ResourceRef{Type: "document", ID: "d1"},
		Input:          map[string]any{"id": "d1", "title": "T", "body": "B"},
		IdempotencyKey: "w1",
	})
	if !w.Allowed {
		t.Fatalf("write: %+v", w.Denial)
	}
	if _, ok := w.Output["internal_notes"]; ok {
		t.Fatal("sensitive field must not appear")
	}

	r := a.Call(ctx, core.Request{
		Operation:   "document.read",
		Credentials: core.Credentials{Token: "tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "d1"},
		Input:       map[string]any{"id": "d1"},
	})
	if !r.Allowed {
		t.Fatalf("read: %+v", r.Denial)
	}
	if r.Output["title"] != "T" {
		t.Fatalf("title=%v", r.Output["title"])
	}
	if _, ok := r.Output["internal_notes"]; ok {
		t.Fatal("internal_notes must be stripped without field grant")
	}
}

func TestDocumentDefaultDenyAndSensitiveStrip(t *testing.T) {
	a, _ := setupDocApp(t)
	// No users
	resp := a.Call(context.Background(), core.Request{
		Operation:   "document.read",
		Credentials: core.Credentials{Token: "nope"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Input:       map[string]any{"id": "1"},
	})
	if resp.Allowed {
		t.Fatal("must deny without principal")
	}

	// Grant read including sensitive field → still need field grant for internal_notes
	_ = a.AddUser("u", "tok", "dev", []string{"document.read"})
	_ = a.GrantOp("u", "dev", "document.read", "document", "*", []string{"id", "title", "body", "internal_notes"})
	resp = a.Call(context.Background(), core.Request{
		Operation:   "document.read",
		Credentials: core.Credentials{Token: "tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Input:       map[string]any{"id": "1"},
	})
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
	// Demo default doc includes internal_notes; with field grant it may pass filter.
	// Without field grant it must not appear — covered above.
}

func TestDocumentWriteRequiresIdempotency(t *testing.T) {
	a, _ := setupDocApp(t)
	_ = a.AddUser("u", "tok", "dev", []string{"document.write"})
	_ = a.GrantOp("u", "dev", "document.write", "document", "*", []string{"id", "title", "status"})
	resp := a.Call(context.Background(), core.Request{
		Operation:   "document.write",
		Credentials: core.Credentials{Token: "tok"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "x"},
		Input:       map[string]any{"id": "x", "title": "t"},
	})
	if resp.Allowed {
		t.Fatal("idempotency required")
	}
	if resp.Denial == nil || resp.Denial.Reason != core.ReasonSchemaInvalid {
		t.Fatalf("want schema_invalid for missing idem key, got %+v", resp.Denial)
	}
}
