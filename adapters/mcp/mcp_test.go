package mcp_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/internal/testtokens"
)

func TestMCPDenyByDefaultNoCredentials(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ad := mcp.New(p.Runtime)
	resp, err := ad.Call(context.Background(), mcp.ToolCall{
		Name:      "document.read",
		Boundary:  "dev",
		Resource:  &core.ResourceRef{Type: "document", ID: "1"},
		Arguments: map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Fatal("no credentials must deny")
	}
}

func TestMCPAllowWithGrantedPrincipal(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ad := mcp.New(p.Runtime)
	resp, err := ad.Call(context.Background(), mcp.ToolCall{
		Name:        "document.read",
		BearerToken: "alice-secret-token",
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Arguments:   map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
}

func TestMCPAllowlistFiltering(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ad := mcp.New(p.Runtime)
	ad.AllowedTools = map[string]struct{}{"document.read": {}}

	// listed tool with granted principal passes through Runtime.Execute
	resp, err := ad.Call(context.Background(), mcp.ToolCall{
		Name:        "document.read",
		BearerToken: "alice-secret-token",
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Arguments:   map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatalf("listed tool must allow: %+v", resp.Denial)
	}

	// unlisted tool blocked before the runtime, even with a valid token
	resp, err = ad.Call(context.Background(), mcp.ToolCall{
		Name:        "payment.capture",
		BearerToken: "bob-finance-token",
		Boundary:    "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Allowed {
		t.Fatal("allowlist must block unlisted tool")
	}
	if resp.Denial == nil || resp.Denial.Step != "mcp" {
		t.Fatalf("expected mcp allowlist denial, got %+v", resp.Denial)
	}
}
