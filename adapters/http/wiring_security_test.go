package http_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/internal/testtokens"
)

func TestHTTPGraphQLWiredAndBypassDenied(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{
		EnableGraphQL: true,
		MCP: &mcp.Server{
			Adapter: mcp.New(p.Runtime), Registry: p.Registry, Verifier: p.Multi,
		},
		Registry: p.Registry,
		Verifier: p.Multi,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Manifest advertises graphql only when wired
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/loom.json", nil))
	if !strings.Contains(rr.Body.String(), "graphql") {
		t.Fatalf("manifest missing graphql: %s", rr.Body.String())
	}

	// Introspection blocked
	rr = httptest.NewRecorder()
	body := `{"query":"{ __schema { queryType { name } } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("introspection code %d body %s", rr.Code, rr.Body.String())
	}

	// Execute via GraphQL with auth
	rr = httptest.NewRecorder()
	gql := `{"query":"mutation { execute(input: { operation: \"document.read\" boundary: \"dev\" input: \"{\\\"id\\\":\\\"1\\\"}\" resource: { type: \"document\" id: \"1\" } }) { allowed } }"}`
	req = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(gql))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), `"allowed":true`) {
		t.Fatalf("graphql execute: %s", rr.Body.String())
	}

	// Bypass header denied
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(gql))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	req.Header.Set("X-Loom-Bypass", "1")
	h.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), `"allowed":true`) {
		t.Fatal("bypass must deny on graphql")
	}
}

func TestHTTPMCPHeaderTokenWinsOverBody(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{
		MCP: &mcp.Server{
			Adapter: mcp.New(p.Runtime), Registry: p.Registry, Verifier: p.Multi,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Authorization = alice; body tries to use bob for tools/list.
	// Header must win → alice tools only (no payment).
	rpc := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params": map[string]any{
			"bearer_token": "bob-finance-token",
		},
	}
	raw, _ := json.Marshal(rpc)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	tools := resp["result"].(map[string]any)["tools"].([]any)
	for _, t0 := range tools {
		name := t0.(map[string]any)["name"].(string)
		if strings.HasPrefix(name, "payment.") {
			t.Fatalf("header alice must win over body bob: saw %s", name)
		}
	}
	if len(tools) == 0 {
		t.Fatal("alice should see tools")
	}
}
