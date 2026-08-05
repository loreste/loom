package bootstrap_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

func TestDistributedPolicyFileSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	// Node A seeds + publishes
	a, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicyPath:               path,
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	// Node B pulls same file
	b, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicyPath:               path,
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	// Alice still works under synced policy
	resp := b.Runtime.Execute(context.Background(), core.Request{
		Operation:   "document.read",
		Credentials: core.Credentials{Token: "alice-secret-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Input:       map[string]any{"id": "1"},
	})
	if !resp.Allowed {
		t.Fatalf("synced policy should allow alice: %+v", resp.Denial)
	}

	// Publish a deny for alice document.read at higher version from A
	src := policy.NewFileSource(path)
	cur, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rules := append([]policy.Rule{}, cur.Rules...)
	rules = append(rules, policy.Rule{
		Principal: "user:alice",
		Boundary:  "dev",
		Operation: "document.read",
		Deny:      true,
		Priority:  999,
	})
	if err := src.Publish(context.Background(), &policy.Document{
		Version: cur.Version + 1,
		ID:      "default",
		Rules:   rules,
	}); err != nil {
		t.Fatal(err)
	}
	// manual sync (interval -1 means no background syncer)
	syncer := policy.NewSyncer(b.PolicySource, b.Policy, time.Second)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	resp = b.Runtime.Execute(context.Background(), core.Request{
		Operation:   "document.read",
		Credentials: core.Credentials{Token: "alice-secret-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Input:       map[string]any{"id": "1"},
	})
	if resp.Allowed {
		t.Fatal("explicit deny after sync must win")
	}
}
