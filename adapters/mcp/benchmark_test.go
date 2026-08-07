package mcp_test

import (
	"context"
	"testing"

	loommcp "github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/internal/testtokens"
)

// BenchmarkCall measures the MCP adapter plus the governed in-memory runtime.
// It intentionally excludes network, PostgreSQL, Redis, and provider latency.
func BenchmarkCall(b *testing.B) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               testtokens.Demo(),
	})
	if err != nil {
		b.Fatal(err)
	}
	adapter := loommcp.New(p.Runtime)
	call := loommcp.ToolCall{
		Name:        "document.read",
		Boundary:    "dev",
		BearerToken: "alice-secret-token",
		Arguments:   map[string]any{"id": "1"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response, err := adapter.Call(context.Background(), call)
		if err != nil || !response.Allowed {
			b.Fatalf("MCP call failed: allowed=%v err=%v", response.Allowed, err)
		}
	}
}
