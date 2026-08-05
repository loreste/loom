package policy_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

// Finding 1: a global (Boundary == "") rule must NOT allow via a fallback that
// skips Permissions/Effect checks. Setup: alice has a boundary-scoped allow for
// "dev" and a global rule requiring the "admin" permission. In "prod", alice
// without the admin capability must be DENIED.
func TestContextualGlobalRuleMustSatisfyPermissions(t *testing.T) {
	eng := policy.NewMemoryEngine()
	if err := eng.AddRule(policy.Rule{Principal: "alice", Boundary: "dev", Operation: "op.x", Priority: 1}); err != nil {
		t.Fatal(err)
	}
	if err := eng.AddRule(policy.Rule{Principal: "alice", Operation: "op.x", Permissions: []string{"admin"}, Priority: 1}); err != nil {
		t.Fatal(err)
	}

	op := &core.Operation{Name: "op.x"}
	req := &core.Request{Operation: "op.x"}

	// Adversary: no admin capability, outside "dev" → must deny.
	dec := eng.EvaluateContextual(context.Background(),
		core.Identity{ID: "alice"}, "prod", op, req)
	if dec.Decision.Allowed() {
		t.Fatalf("global rule bypassed permission check: %v", dec)
	}

	// Same adversary in "dev": boundary-specific rule legitimately allows.
	dec = eng.EvaluateContextual(context.Background(),
		core.Identity{ID: "alice"}, "dev", op, req)
	if !dec.Decision.Allowed() {
		t.Fatalf("boundary-scoped rule should allow in dev: %v", dec)
	}

	// Holder of the admin capability: global rule matches via main loop.
	dec = eng.EvaluateContextual(context.Background(),
		core.Identity{ID: "alice", Capabilities: []string{"admin"}}, "prod", op, req)
	if !dec.Decision.Allowed() {
		t.Fatalf("global rule with satisfied permissions should allow: %v", dec)
	}
}

// Finding 1 (cont.): removing the fallback must not weaken deny-overrides —
// a global deny rule still beats a boundary-scoped allow at equal priority.
func TestContextualGlobalDenyStillOverrides(t *testing.T) {
	eng := policy.NewMemoryEngine()
	if err := eng.AddRule(policy.Rule{Principal: "alice", Boundary: "prod", Operation: "op.x", Priority: 5}); err != nil {
		t.Fatal(err)
	}
	if err := eng.AddRule(policy.Rule{Principal: "alice", Operation: "op.x", Deny: true, Priority: 5}); err != nil {
		t.Fatal(err)
	}
	dec := eng.EvaluateContextual(context.Background(),
		core.Identity{ID: "alice"}, "prod",
		&core.Operation{Name: "op.x"}, &core.Request{Operation: "op.x"})
	if dec.Decision.Allowed() {
		t.Fatalf("global deny must override boundary allow: %v", dec)
	}
}

// Finding 3: bypass tripwire headers deny on ANY non-empty value, and keys
// are matched case-insensitively.
func TestBypassHeadersDenied(t *testing.T) {
	cases := []map[string]string{
		{"x-admin-override": "yes"},   // previously allowed (not "true"/"1")
		{"x-admin-override": "0"},     // any non-empty value denies
		{"X-Admin-Override": "true"},  // mixed-case key
		{"X-LOOM-BYPASS": "1"},        // upper-case key
		{"x-LoOm-ByPaSs": "yes"},      // mixed-case key
	}
	for _, md := range cases {
		eng := policy.NewMemoryEngine()
		if err := eng.AddRule(policy.Rule{Principal: "alice", Operation: "op.x", Priority: 1}); err != nil {
			t.Fatal(err)
		}
		req := &core.Request{Operation: "op.x", Metadata: md}
		dec := eng.EvaluateContextual(context.Background(),
			core.Identity{ID: "alice"}, "prod",
			&core.Operation{Name: "op.x"}, req)
		if dec.Decision.Allowed() {
			t.Fatalf("bypass metadata %v must deny", md)
		}
	}

	// Control: empty value is not a tripwire; the allow rule wins.
	eng := policy.NewMemoryEngine()
	if err := eng.AddRule(policy.Rule{Principal: "alice", Operation: "op.x", Priority: 1}); err != nil {
		t.Fatal(err)
	}
	req := &core.Request{Operation: "op.x", Metadata: map[string]string{
		"X-Admin-Override": "",
		"unrelated":        "fine",
	}}
	dec := eng.EvaluateContextual(context.Background(),
		core.Identity{ID: "alice"}, "prod",
		&core.Operation{Name: "op.x"}, req)
	if !dec.Decision.Allowed() {
		t.Fatalf("empty bypass header value should not deny: %v", dec)
	}
}

// gatedSource hands out pre-assigned documents and blocks every caller inside
// Load until all callers have entered, maximizing the check-then-apply race
// window between concurrent SyncOnce calls.
type gatedSource struct {
	mu      sync.Mutex
	docs    []*policy.Document
	entered int
	gate    chan struct{}
}

func newGatedSource(docs ...*policy.Document) *gatedSource {
	return &gatedSource{docs: docs, gate: make(chan struct{})}
}

func (s *gatedSource) Load(_ context.Context) (*policy.Document, error) {
	s.mu.Lock()
	doc := s.docs[s.entered]
	s.entered++
	if s.entered == len(s.docs) {
		close(s.gate)
	}
	s.mu.Unlock()
	<-s.gate
	return doc, nil
}

func (s *gatedSource) Publish(context.Context, *policy.Document) error { return nil }

// Finding 4: concurrent SyncOnce callers must be serialized so a stale
// version can never be applied after a newer one.
func TestSyncOnceConcurrentStaleVersionNeverRegresses(t *testing.T) {
	for i := 0; i < 100; i++ {
		eng := policy.NewMemoryEngine()
		stale := &policy.Document{Version: 1, Rules: []policy.Rule{
			{Principal: "stale", Operation: "op.x", Priority: 1},
		}}
		fresh := &policy.Document{Version: 2, Rules: []policy.Rule{
			{Principal: "fresh", Operation: "op.y", Priority: 1},
		}}
		src := newGatedSource(stale, fresh)
		syncer := policy.NewSyncer(src, eng, time.Second)

		var wg sync.WaitGroup
		wg.Add(2)
		for j := 0; j < 2; j++ {
			go func() {
				defer wg.Done()
				_ = syncer.SyncOnce(context.Background())
			}()
		}
		wg.Wait()

		if got := syncer.AppliedVersion(); got != 2 {
			t.Fatalf("iter %d: applied version regressed to %d", i, got)
		}
		rules := eng.Snapshot()
		if len(rules) != 1 || rules[0].Principal != "fresh" {
			t.Fatalf("iter %d: stale rules applied: %+v", i, rules)
		}
	}
}
