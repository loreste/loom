package boundary_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/boundary"
	"github.com/loreste/loom/core"
)

func TestMemoryCheckerMemberAllowed(t *testing.T) {
	c := boundary.NewMemoryChecker()
	if err := c.Grant("user:alice", "dev"); err != nil {
		t.Fatal(err)
	}
	if err := c.Allow(context.Background(), core.Identity{ID: "user:alice"}, "dev"); err != nil {
		t.Fatalf("member must be allowed: %v", err)
	}
}

func TestMemoryCheckerCrossTenantDenied(t *testing.T) {
	c := boundary.NewMemoryChecker()
	if err := c.Grant("user:alice", "dev"); err != nil {
		t.Fatal(err)
	}
	// granted in dev, requesting prod
	if err := c.Allow(context.Background(), core.Identity{ID: "user:alice"}, "prod"); err == nil {
		t.Fatal("cross-tenant grant lookup must deny")
	}
}

func TestMemoryCheckerUnknownPrincipalDenied(t *testing.T) {
	c := boundary.NewMemoryChecker()
	if err := c.Allow(context.Background(), core.Identity{ID: "user:ghost"}, "dev"); err == nil {
		t.Fatal("unknown principal must deny")
	}
}

func TestMemoryCheckerEmptyBoundaryDenied(t *testing.T) {
	c := boundary.NewMemoryChecker()
	if err := c.Grant("user:alice", "dev"); err != nil {
		t.Fatal(err)
	}
	if err := c.Allow(context.Background(), core.Identity{ID: "user:alice"}, ""); err == nil {
		t.Fatal("empty boundary must deny")
	}
}

func TestMemoryCheckerHomeBoundaryPinned(t *testing.T) {
	c := boundary.NewMemoryChecker()
	if err := c.Grant("user:alice", "dev"); err != nil {
		t.Fatal(err)
	}
	if err := c.Grant("user:alice", "staging"); err != nil {
		t.Fatal(err)
	}
	// identity pinned to dev cannot act in staging even with a grant
	if err := c.Allow(context.Background(), core.Identity{ID: "user:alice", Boundary: "dev"}, "staging"); err == nil {
		t.Fatal("home-boundary pinning must deny cross-boundary spoof")
	}
	// matching home boundary still allowed
	if err := c.Allow(context.Background(), core.Identity{ID: "user:alice", Boundary: "dev"}, "dev"); err != nil {
		t.Fatalf("home boundary must allow: %v", err)
	}
}

func TestMemoryCheckerRevokeDenies(t *testing.T) {
	c := boundary.NewMemoryChecker()
	if err := c.Grant("user:alice", "dev"); err != nil {
		t.Fatal(err)
	}
	c.Revoke("user:alice", "dev")
	if err := c.Allow(context.Background(), core.Identity{ID: "user:alice"}, "dev"); err == nil {
		t.Fatal("revoked membership must deny")
	}
}
