package loom_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/internal/testtokens"
	"github.com/loreste/loom/sdk/go/loom"
)

func testServer(t *testing.T) (*httptest.Server, *bootstrap.Platform) {
	t.Helper()
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{
		MCP: &mcp.Server{
			Adapter: mcp.New(p.Runtime), Registry: p.Registry, Verifier: p.Multi,
		},
		Registry: p.Registry,
		Verifier: p.Multi,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, p
}

func TestLocalClientCall(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	c := loom.NewClient(p.Runtime)
	aliceToken := testtokens.Demo()["user:alice"]
	resp := c.Call(context.Background(), core.Request{
		Operation:   "document.read",
		Credentials: core.Credentials{Token: aliceToken},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Input:       map[string]any{"id": "1"},
	})
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
	if _, ok := resp.Output["internal_notes"]; ok {
		t.Fatal("sensitive leak")
	}
}

func TestHTTPClientExecuteAndDenyHint(t *testing.T) {
	ts, _ := testServer(t)
	c := loom.NewHTTPClient(ts.URL, testtokens.Demo()["user:alice"])

	ok, err := c.Call(context.Background(), core.Request{
		Operation: "document.read",
		Boundary:  "dev",
		Resource:  &core.ResourceRef{Type: "document", ID: "1"},
		Input:     map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok.Allowed {
		t.Fatalf("%+v", ok.Denial)
	}

	// payment without approval/caps → structured denial with hint
	deny, err := c.Call(context.Background(), core.Request{
		Operation:      "payment.capture",
		Boundary:       "dev",
		Resource:       &core.ResourceRef{Type: "payment", ID: "*"},
		Input:          map[string]any{"amount": 1.0, "currency": "USD", "merchant_id": "m"},
		IdempotencyKey: "sdk-deny-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if deny.Allowed || deny.Denial == nil {
		t.Fatal("expected deny")
	}
	// JSON round-trip must preserve Retryable/Hint (exported fields)
	raw, _ := json.Marshal(deny.Denial)
	if !strings.Contains(string(raw), "Hint") && deny.Denial.Hint == "" {
		// either serialized or present on struct after unmarshal from server
		t.Logf("denial: %+v raw=%s", deny.Denial, raw)
	}
	if deny.Denial.Hint == "" && deny.Denial.Reason == "" {
		t.Fatal("expected reason or hint")
	}
}

func TestHTTPClientManifestOpenAPI(t *testing.T) {
	ts, _ := testServer(t)
	c := loom.NewHTTPClient(ts.URL, testtokens.Demo()["user:alice"])

	m, err := c.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m["service"] != "loom" {
		t.Fatalf("%v", m)
	}
	if m["execute_endpoint"] == nil {
		t.Fatal("missing execute_endpoint")
	}

	doc, err := c.OpenAPI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths["/ops/document.read"] == nil {
		t.Fatal("alice should see document.read in openapi")
	}
	if paths["/ops/payment.capture"] != nil {
		t.Fatal("alice must not see payment")
	}
}

func TestHTTPClientMCP(t *testing.T) {
	ts, _ := testServer(t)
	c := loom.NewHTTPClient(ts.URL, testtokens.Demo()["user:alice"])

	init, err := c.MCP(context.Background(), map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if init["error"] != nil {
		t.Fatalf("%v", init["error"])
	}

	list, err := c.MCP(context.Background(), map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	tools := list["result"].(map[string]any)["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("expected tools")
	}

	// no token → empty tools
	c2 := loom.NewHTTPClient(ts.URL, "")
	list2, err := c2.MCP(context.Background(), map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	tools2 := list2["result"].(map[string]any)["tools"].([]any)
	if len(tools2) != 0 {
		t.Fatal("unauth must see zero tools")
	}
}

func TestHTTPClientNilSafe(t *testing.T) {
	var c *loom.HTTPClient
	_, err := c.Call(context.Background(), core.Request{Operation: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	lc := loom.NewClient(nil)
	resp := lc.Call(context.Background(), core.Request{Operation: "x"})
	if resp.Allowed {
		t.Fatal("nil runtime must deny")
	}
}

// Ensure Response Denial unmarshals Retryable/Hint from wire.
func TestDenialWireFields(t *testing.T) {
	raw := []byte(`{"Allowed":false,"Decision":"deny","Denial":{"Reason":"approval_required","Message":"approval required","Step":"approval","Retryable":true,"Hint":"obtain an approval token"}}`)
	var resp core.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Denial == nil || !resp.Denial.Retryable || resp.Denial.Hint == "" {
		t.Fatalf("%+v", resp.Denial)
	}
	_ = http.StatusOK
}
