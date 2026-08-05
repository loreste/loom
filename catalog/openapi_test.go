package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/loreste/loom/core"
)

func TestOpenAPIFromSpecs(t *testing.T) {
	reg := regWith(t,
		&core.Operation{
			Name:            "document.read",
			Description:     "Read a document",
			InputSchema:     json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`),
			Permissions:     []string{"document.read"},
			Risk:            core.RiskLow,
			SensitiveFields: []string{"internal_notes"},
		},
		&core.Operation{
			Name:        "payment.capture",
			Description: "Capture",
			InputSchema: json.RawMessage(`{"type":"object"}`),
			Permissions: []string{"payment.capture"},
			Risk:        core.RiskHigh,
			Approval:    core.ApprovalPolicy{MinRisk: core.RiskHigh},
			Idempotency: core.IdempotencyPolicy{Required: true},
		},
	)
	// Only document.read visible
	specs := Build(reg, ForCapabilities([]string{"document.read"}))
	doc := OpenAPI("loom", specs, OpenAPIOptions{ServerURL: "https://example.test"})

	if doc["openapi"] != "3.0.3" {
		t.Fatalf("openapi=%v", doc["openapi"])
	}
	paths, _ := doc["paths"].(map[string]any)
	if paths["/v1/execute"] == nil {
		t.Fatal("missing execute path")
	}
	if paths["/ops/document.read"] == nil {
		t.Fatal("missing document.read path")
	}
	// Filtered: payment must not appear
	if paths["/ops/payment.capture"] != nil {
		t.Fatal("payment path must not appear without capability")
	}
	// Sensitive field names must not leak
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), "internal_notes") {
		t.Fatal("sensitive field name leaked into OpenAPI")
	}
	// x-loom extensions present
	post := paths["/ops/document.read"].(map[string]any)["post"].(map[string]any)
	if post["x-loom-operation"] != "document.read" {
		t.Fatalf("x-loom-operation=%v", post["x-loom-operation"])
	}
	if post["x-loom-sensitive-fields"] != true {
		t.Fatal("expected sensitive flag")
	}
	if doc["servers"] == nil {
		t.Fatal("servers missing")
	}
}

func TestOpenAPIEmptySpecsStillHasExecute(t *testing.T) {
	doc := OpenAPI("loom", nil, OpenAPIOptions{})
	paths := doc["paths"].(map[string]any)
	if len(paths) != 1 || paths["/v1/execute"] == nil {
		t.Fatalf("paths=%v", paths)
	}
}
