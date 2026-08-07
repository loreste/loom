package weft_test

import (
	"context"
	"testing"

	loomweft "github.com/loreste/loom/adapters/weft"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/internal/testtokens"
)

// BenchmarkInvoke measures Weft translation plus the governed in-memory
// runtime. Weft has no privileged execution path.
func BenchmarkInvoke(b *testing.B) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               testtokens.Demo(),
	})
	if err != nil {
		b.Fatal(err)
	}
	adapter := loomweft.New(p.Runtime)
	call := loomweft.StepCall{
		WorkflowID:  "benchmark-workflow",
		StepID:      "read",
		Operation:   "document.read",
		Boundary:    "dev",
		BearerToken: "alice-secret-token",
		Input:       map[string]any{"id": "1"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response, err := adapter.Invoke(context.Background(), call)
		if err != nil || !response.Allowed {
			b.Fatalf("Weft call failed: allowed=%v err=%v", response.Allowed, err)
		}
	}
}
