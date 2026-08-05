package tenancy_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/tenancy"
)

func TestResolverRejectsMissingAndConflictingTenant(t *testing.T) {
	r, err := tenancy.NewResolver("tenant_id")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	base := core.Identity{ID: "user:a", Attributes: map[string]string{"tenant_id": "tenant-a"}}
	if _, err := r.Resolve(ctx, base, "tenant-b"); err == nil {
		t.Fatal("conflicting tenant claim must deny")
	}
	if _, err := r.Resolve(ctx, core.Identity{ID: "user:a"}, "tenant-a"); err == nil {
		t.Fatal("missing tenant claim must deny")
	}
	if got, err := r.Resolve(ctx, base, "tenant-a"); err != nil || got != "tenant-a" {
		t.Fatalf("matching tenant claim: %q %v", got, err)
	}
}

func TestResolverRejectsEmptyBoundary(t *testing.T) {
	r, _ := tenancy.NewResolver("tenant_id")
	_, err := r.Resolve(context.Background(), core.Identity{
		ID: "user:a", Attributes: map[string]string{"tenant_id": "tenant-a"},
	}, "")
	if err == nil {
		t.Fatal("empty boundary must deny")
	}
}
