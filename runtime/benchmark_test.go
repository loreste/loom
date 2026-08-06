package runtime

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
)

// BenchmarkExecuteGranted measures the in-process enforcement path only. It
// excludes network, PostgreSQL, Redis, and external identity-provider latency.
func BenchmarkExecuteGranted(b *testing.B) {
	stack, err := NewTestStack()
	if err != nil {
		b.Fatal(err)
	}
	if err := stack.Verifier.Register(identity.StaticPrincipal{
		ID: "benchmark-user", Type: "service", Boundary: "benchmark", Token: "benchmark-token",
		Capabilities: []string{"profile.read"},
	}); err != nil {
		b.Fatal(err)
	}
	if err := stack.Boundary.Grant("benchmark-user", "benchmark"); err != nil {
		b.Fatal(err)
	}
	if err := stack.Policy.AddRule(policy.Rule{
		Principal: "benchmark-user", Boundary: "benchmark", Operation: "profile.read",
		OperationVersion: "1", Priority: 1,
	}); err != nil {
		b.Fatal(err)
	}
	if err := stack.Registry.Register(&core.Operation{
		Name: "profile.read", Version: "1", Permissions: []string{"profile.read"},
		Risk: core.RiskLow, Effects: []core.Effect{core.EffectRead},
	}, func(*core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{"status": "ok"}}, nil
	}); err != nil {
		b.Fatal(err)
	}
	req := core.Request{
		Operation: "profile.read", OperationVersion: "1", Boundary: "benchmark",
		Credentials: core.Credentials{Scheme: "bearer", Token: "benchmark-token"},
		Input:       map[string]any{"id": "profile-1"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response := stack.Runtime.Execute(context.Background(), req)
		if !response.Allowed {
			b.Fatalf("benchmark request denied: %+v", response.Denial)
		}
	}
}
