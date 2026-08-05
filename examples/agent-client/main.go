// Command agent-client walks the agent discovery path against an in-process Loom edge.
//
// No custom REST API: discover → learn tools → invoke through the same governed path.
//
//	go run ./examples/agent-client/
//
// Flow:
//  1. GET  /.well-known/loom.json   (unauthenticated manifest)
//  2. GET  /v1/openapi.json         (capability-filtered OpenAPI)
//  3. catalog.spec via /v1/execute  (full tool specs)
//  4. tools/list + tools/call via POST /mcp
//  5. document.read via POST /v1/execute
//  6. Adversarial: payment.capture denied (alice has no payment caps)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/sdk/go/loom"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	if err != nil {
		return err
	}
	defer p.Close()

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
		return err
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Alice = product user / light agent persona
	c := loom.NewHTTPClient(ts.URL, "alice-secret-token")

	fmt.Println("== 1. Manifest (unauthenticated discovery) ==")
	// Manifest does not need a token; use a throwaway client.
	pub := loom.NewHTTPClient(ts.URL, "")
	manifest, err := pub.Manifest(ctx)
	if err != nil {
		return err
	}
	printJSON(manifest)
	for _, leak := range []string{"payment.capture", "document.read", "alice"} {
		raw, _ := json.Marshal(manifest)
		if strings.Contains(string(raw), leak) {
			return fmt.Errorf("manifest leaked %q", leak)
		}
	}

	fmt.Println("\n== 2. OpenAPI (capability-filtered) ==")
	doc, err := c.OpenAPI(ctx)
	if err != nil {
		return err
	}
	paths, _ := doc["paths"].(map[string]any)
	var opPaths []string
	for k := range paths {
		if strings.HasPrefix(k, "/ops/") {
			opPaths = append(opPaths, k)
		}
	}
	fmt.Printf("ops visible to alice: %v\n", opPaths)
	if paths["/ops/payment.capture"] != nil {
		return fmt.Errorf("alice must not see payment.capture in OpenAPI")
	}
	if paths["/ops/document.read"] == nil {
		return fmt.Errorf("alice should see document.read in OpenAPI")
	}

	fmt.Println("\n== 3. catalog.spec (governed tool list) ==")
	spec, err := c.CatalogSpec(ctx, "dev")
	if err != nil {
		return err
	}
	if !spec.Allowed {
		return fmt.Errorf("catalog.spec denied: %+v", spec.Denial)
	}
	tools, _ := spec.Output["tools"].([]any)
	fmt.Printf("tool count=%d\n", len(tools))
	for _, t := range tools {
		m, _ := t.(map[string]any)
		name, _ := m["name"].(string)
		if strings.HasPrefix(name, "payment.") {
			return fmt.Errorf("catalog.spec leaked %s", name)
		}
		fmt.Printf("  - %s risk=%v approval=%v\n", name, m["risk"], m["approval_required"])
	}

	fmt.Println("\n== 4. MCP tools/list + tools/call ==")
	list, err := c.MCP(ctx, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{},
	})
	if err != nil {
		return err
	}
	if list["error"] != nil {
		return fmt.Errorf("tools/list error: %v", list["error"])
	}
	mcpTools, _ := list["result"].(map[string]any)["tools"].([]any)
	fmt.Printf("mcp tools=%d\n", len(mcpTools))

	call, err := c.MCP(ctx, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "document.read",
			"arguments": map[string]any{"id": "agent-demo-1"},
			"boundary":  "dev",
			"resource":  map[string]any{"type": "document", "id": "agent-demo-1"},
		},
	})
	if err != nil {
		return err
	}
	result, _ := call["result"].(map[string]any)
	if result["isError"] == true {
		return fmt.Errorf("tools/call failed: %v", result)
	}
	fmt.Println("tools/call document.read ok")

	fmt.Println("\n== 5. Execute document.read ==")
	read, err := c.Call(ctx, core.Request{
		Operation: "document.read",
		Boundary:  "dev",
		Resource:  &core.ResourceRef{Type: "document", ID: "agent-demo-1"},
		Input:     map[string]any{"id": "agent-demo-1"},
	})
	if err != nil {
		return err
	}
	if !read.Allowed {
		return fmt.Errorf("document.read denied: %+v", read.Denial)
	}
	if _, ok := read.Output["internal_notes"]; ok {
		return fmt.Errorf("sensitive field leaked")
	}
	printJSON(read.Output)

	fmt.Println("\n== 6. Adversarial: payment.capture denied ==")
	deny, err := c.Call(ctx, core.Request{
		Operation:      "payment.capture",
		Boundary:       "dev",
		Resource:       &core.ResourceRef{Type: "payment", ID: "*"},
		Input:          map[string]any{"amount": 1.0, "currency": "USD", "merchant_id": "m"},
		IdempotencyKey: "agent-client-pay-1",
	})
	if err != nil {
		return err
	}
	if deny.Allowed {
		return fmt.Errorf("alice must not capture payments")
	}
	fmt.Printf("denied reason=%s hint=%q retryable=%v\n",
		deny.Denial.Reason, deny.Denial.Hint, deny.Denial.Retryable)

	fmt.Println("\nagent-client ok")
	return nil
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}
