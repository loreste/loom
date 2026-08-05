package graphql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	loomgql "github.com/loreste/loom/adapters/graphql"
	"github.com/loreste/loom/bootstrap"
)

func TestGraphQLHealth(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	res, err := loomgql.Do(context.Background(), p.Runtime, `{ health }`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) > 0 {
		t.Fatalf("%v", res.Errors)
	}
	data := res.Data.(map[string]any)
	if data["health"] != "ok" {
		t.Fatalf("%v", data)
	}
}

func TestGraphQLExecuteAllow(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	q := `mutation($in: ExecuteInput!) {
		execute(input: $in) {
			allowed denial { reason hint } output risk
		}
	}`
	vars := map[string]any{
		"in": map[string]any{
			"operation": "document.read",
			"boundary":  "dev",
			"input":     `{"id":"1"}`,
			"resource":  map[string]any{"type": "document", "id": "1"},
		},
	}
	ctx := loomgql.WithToken(context.Background(), "alice-secret-token")
	res, err := loomgql.Do(ctx, p.Runtime, q, vars)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) > 0 {
		t.Fatalf("%v", res.Errors)
	}
	exec := res.Data.(map[string]any)["execute"].(map[string]any)
	if exec["allowed"] != true {
		t.Fatalf("%v", exec)
	}
	out, _ := exec["output"].(string)
	if strings.Contains(out, "internal_notes") {
		t.Fatal("sensitive leak")
	}
}

func TestGraphQLExecuteDenyNoAuth(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	t.Cleanup(func() { _ = p.Close() })

	q := `mutation {
		execute(input: {
			operation: "document.read"
			boundary: "dev"
			input: "{\"id\":\"1\"}"
			resource: { type: "document", id: "1" }
		}) { allowed denial { reason } }
	}`
	res, err := loomgql.Do(context.Background(), p.Runtime, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	exec := res.Data.(map[string]any)["execute"].(map[string]any)
	if exec["allowed"] != false {
		t.Fatal("must deny")
	}
}

func TestGraphQLBypassHeaderDenied(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	t.Cleanup(func() { _ = p.Close() })
	h, err := loomgql.Handler(p.Runtime)
	if err != nil {
		t.Fatal(err)
	}

	body := map[string]any{
		"query": `mutation {
			execute(input: {
				operation: "document.read"
				boundary: "dev"
				input: "{\"id\":\"1\"}"
				resource: { type: "document", id: "1" }
			}) { allowed }
		}`,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	req.Header.Set("X-Loom-Bypass", "1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("code %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	data := out["data"].(map[string]any)["execute"].(map[string]any)
	if data["allowed"] != false {
		t.Fatal("bypass must deny")
	}
}

func TestGraphQLHTTPHandlerAllow(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	t.Cleanup(func() { _ = p.Close() })
	h, err := loomgql.Handler(p.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"query":"mutation { execute(input: { operation: \"document.read\" boundary: \"dev\" input: \"{\\\"id\\\":\\\"1\\\"}\" resource: { type: \"document\" id: \"1\" } }) { allowed } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), `"allowed":true`) {
		t.Fatalf("%s", rr.Body.String())
	}
}
