package http_test

import (
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

func platformHTTP(t *testing.T) (*bootstrap.Platform, http.Handler) {
	t.Helper()
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DemoTokens: testtokens.Demo()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{
		MCP: &mcp.Server{
			Adapter:  mcp.New(p.Runtime),
			Registry: p.Registry,
			Verifier: p.Multi,
		},
		Registry: p.Registry,
		Verifier: p.Multi,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, srv.Handler()
}

func TestHTTPMCPToolsCall(t *testing.T) {
	_, h := platformHTTP(t)

	// initialize
	rr := httptest.NewRecorder()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("code %d body %s", rr.Code, rr.Body.String())
	}

	// tools/list with alice auth via Authorization header
	rr = httptest.NewRecorder()
	body = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("list code %d %s", rr.Code, rr.Body.String())
	}
	var listResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
		t.Fatal(err)
	}
	if listResp["error"] != nil {
		t.Fatalf("rpc error: %v", listResp["error"])
	}
	tools := listResp["result"].(map[string]any)["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("alice should see tools")
	}
	for _, raw := range tools {
		name := raw.(map[string]any)["name"].(string)
		if strings.HasPrefix(name, "payment.") {
			t.Fatalf("alice must not see %s", name)
		}
	}

	// tools/list without auth → empty
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	h.ServeHTTP(rr, req)
	_ = json.Unmarshal(rr.Body.Bytes(), &listResp)
	tools = listResp["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 0 {
		t.Fatalf("unauth tools must be empty, got %d", len(tools))
	}

	// tools/call document.read
	rr = httptest.NewRecorder()
	call := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "document.read",
			"arguments": map[string]any{"id": "1"},
			"boundary":  "dev",
			"resource":  map[string]any{"type": "document", "id": "1"},
		},
	}
	b, _ := json.Marshal(call)
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("call code %d %s", rr.Code, rr.Body.String())
	}
	var callResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &callResp); err != nil {
		t.Fatal(err)
	}
	if callResp["error"] != nil {
		t.Fatalf("rpc error: %v", callResp["error"])
	}
	result := callResp["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("expected allow: %v", result)
	}
	loomExt, _ := result["_loom"].(map[string]any)
	if loomExt != nil {
		if out, ok := loomExt["output"].(map[string]any); ok {
			if _, leak := out["internal_notes"]; leak {
				t.Fatal("sensitive field leaked via MCP")
			}
		}
	}

	// GET /mcp not allowed
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mcp: %d", rr.Code)
	}
}

func TestHTTPOpenAPIFiltered(t *testing.T) {
	_, h := platformHTTP(t)

	// no auth → only execute path (no op schemas)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/openapi.json", nil))
	if rr.Code != 200 {
		t.Fatalf("code %d", rr.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	if paths["/v1/execute"] == nil {
		t.Fatal("execute required")
	}
	for k := range paths {
		if strings.HasPrefix(k, "/ops/") {
			t.Fatalf("unauth openapi leaked %s", k)
		}
	}

	// alice sees document, not payment
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/openapi.json", nil)
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	paths = doc["paths"].(map[string]any)
	if paths["/ops/document.read"] == nil {
		t.Fatal("alice should see document.read")
	}
	if paths["/ops/payment.capture"] != nil {
		t.Fatal("alice must not see payment.capture")
	}
	raw := rr.Body.String()
	if strings.Contains(raw, "internal_notes") {
		t.Fatal("sensitive field name in openapi")
	}
}

func TestHTTPManifestListsAgentEndpoints(t *testing.T) {
	_, h := platformHTTP(t)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/loom.json", nil))
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["mcp_endpoint"] != "POST /mcp" {
		t.Fatalf("mcp_endpoint=%v", m["mcp_endpoint"])
	}
	if m["openapi_endpoint"] != "GET /v1/openapi.json" {
		t.Fatalf("openapi_endpoint=%v", m["openapi_endpoint"])
	}
	// still no op names
	for _, leak := range []string{"payment.capture", "document.read"} {
		if strings.Contains(rr.Body.String(), leak) {
			t.Fatalf("leaked %s", leak)
		}
	}
}
