package grpc_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	loomgrpc "github.com/loreste/loom/adapters/grpc"
	loomv1 "github.com/loreste/loom/adapters/grpc/gen/loom/v1"
	"github.com/loreste/loom/bootstrap"
)

const bufSize = 1 << 20

func startGRPC(t *testing.T) (loomv1.RuntimeClient, func()) {
	t.Helper()
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(bufSize)
	gs := grpc.NewServer()
	if err := loomgrpc.Register(gs, p.Runtime); err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		_ = conn.Close()
		gs.Stop()
		_ = p.Close()
	}
	return loomv1.NewRuntimeClient(conn), cleanup
}

func TestGRPCExecuteAllow(t *testing.T) {
	client, cleanup := startGRPC(t)
	defer cleanup()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer alice-secret-token",
	))
	resp, err := client.Execute(ctx, &loomv1.ExecuteRequest{
		Operation:    "document.read",
		Boundary:     "dev",
		InputJson:    `{"id":"1"}`,
		ResourceType: "document",
		ResourceId:   "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatalf("deny: %s %s", resp.DenialReason, resp.DenialHint)
	}
	if resp.OutputJson == "" {
		t.Fatal("expected output")
	}
	if contains(resp.OutputJson, "internal_notes") {
		t.Fatal("sensitive field leaked")
	}
}

func TestGRPCExecuteUnauthenticated(t *testing.T) {
	client, cleanup := startGRPC(t)
	defer cleanup()

	resp, err := client.Execute(context.Background(), &loomv1.ExecuteRequest{
		Operation:    "document.read",
		Boundary:     "dev",
		InputJson:    `{"id":"1"}`,
		ResourceType: "document",
		ResourceId:   "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Fatal("must deny without token")
	}
}

func TestGRPCBypassMetadataHardDenied(t *testing.T) {
	client, cleanup := startGRPC(t)
	defer cleanup()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer alice-secret-token",
		"x-loom-bypass", "true",
	))
	resp, err := client.Execute(ctx, &loomv1.ExecuteRequest{
		Operation:    "document.read",
		Boundary:     "dev",
		InputJson:    `{"id":"1"}`,
		ResourceType: "document",
		ResourceId:   "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Fatal("bypass must never allow")
	}
}

func TestGRPCPaymentDeniedForAlice(t *testing.T) {
	client, cleanup := startGRPC(t)
	defer cleanup()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer alice-secret-token",
	))
	resp, err := client.Execute(ctx, &loomv1.ExecuteRequest{
		Operation:      "payment.capture",
		Boundary:       "dev",
		InputJson:      `{"amount":1,"currency":"USD","merchant_id":"m"}`,
		ResourceType:   "payment",
		ResourceId:     "*",
		IdempotencyKey: "grpc-pay-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Fatal("alice must not capture")
	}
	if resp.DenialHint == "" {
		t.Fatal("expected agent-actionable hint")
	}
}

func TestGRPCInvalidInputJSON(t *testing.T) {
	client, cleanup := startGRPC(t)
	defer cleanup()

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer alice-secret-token",
	))
	_, err := client.Execute(ctx, &loomv1.ExecuteRequest{
		Operation: "document.read",
		Boundary:  "dev",
		InputJson: `{not-json`,
	})
	if err == nil {
		t.Fatal("expected invalid argument")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && (func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})()))
}
