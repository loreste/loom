package policy_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

func TestFilePolicyPublishAndSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	src := policy.NewFileSource(path)
	eng := policy.NewMemoryEngine()
	_ = eng.AddRule(policy.Rule{Principal: "user:a", Operation: "op.a", Priority: 1})

	// empty store
	if _, err := src.Load(context.Background()); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("expected core.ErrNotFound, got %v", err)
	}

	doc := &policy.Document{
		Version: 1,
		Rules: []policy.Rule{
			{Principal: "user:b", Boundary: "dev", Operation: "document.read", Priority: 5},
		},
	}
	if err := src.Publish(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	// non-increasing rejected
	if err := src.Publish(context.Background(), doc); err == nil {
		t.Fatal("expected version reject")
	}

	syncer := policy.NewSyncer(src, eng, time.Second)
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if syncer.AppliedVersion() != 1 {
		t.Fatalf("version %d", syncer.AppliedVersion())
	}
	if eng.RuleCount() != 1 {
		t.Fatalf("rules %d", eng.RuleCount())
	}

	// corrupt apply must not wipe: publish bad via raw file
	// newer version with valid rules
	doc2 := &policy.Document{
		Version: 2,
		Rules: []policy.Rule{
			{Principal: "user:c", Operation: "x.y", Priority: 1},
			{Principal: "user:d", Operation: "x.z", Priority: 1},
		},
	}
	_ = src.Publish(context.Background(), doc2)
	_ = syncer.SyncOnce(context.Background())
	if eng.RuleCount() != 2 || syncer.AppliedVersion() != 2 {
		t.Fatalf("v2 apply failed count=%d ver=%d", eng.RuleCount(), syncer.AppliedVersion())
	}
}

func TestReplaceRulesDenyAll(t *testing.T) {
	eng := policy.NewMemoryEngine()
	_ = eng.AddRule(policy.Rule{Operation: "a", Priority: 1})
	if err := eng.ReplaceRules(nil); err != nil {
		t.Fatal(err)
	}
	dec := eng.CheckOperationPermission(context.Background(), core.Identity{ID: "x"}, &core.Operation{Name: "a"})
	if dec.Decision.Allowed() {
		t.Fatal("empty rules must deny")
	}
}
