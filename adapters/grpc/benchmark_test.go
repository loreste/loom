package grpc_test

import (
	"context"
	"testing"

	loomgrpc "github.com/loreste/loom/adapters/grpc"
	loomv1 "github.com/loreste/loom/adapters/grpc/gen/loom/v1"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/internal/testtokens"
	"google.golang.org/grpc/metadata"
)

// BenchmarkExecute measures the gRPC service method plus the governed
// in-memory runtime. It excludes listener, PostgreSQL, Redis, and provider
// latency; deployment benchmarks must measure those separately.
func BenchmarkExecute(b *testing.B) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               testtokens.Demo(),
	})
	if err != nil {
		b.Fatal(err)
	}
	server, err := loomgrpc.NewServer(p.Runtime)
	if err != nil {
		b.Fatal(err)
	}
	request := &loomv1.ExecuteRequest{
		Operation:        "document.read",
		OperationVersion: "1",
		Boundary:         "dev",
		InputJson:        `{"id":"1"}`,
		ResourceType:     "document",
		ResourceId:       "1",
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer alice-secret-token",
	))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response, err := server.Execute(ctx, request)
		if err != nil || !response.Allowed {
			b.Fatalf("gRPC call failed: allowed=%v err=%v", response.Allowed, err)
		}
	}
}
