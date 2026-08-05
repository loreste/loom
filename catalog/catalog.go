// Package catalog generates tool specifications from the operation registry.
// Specs describe how to call an operation; they never grant invoke rights —
// policy still enforces at runtime.
package catalog

import (
	"encoding/json"
	"sort"

	"github.com/loreste/loom/core"
)

// ToolSpec is the agent-facing descriptor for one operation.
// Sensitive field names are never exposed — only a presence flag.
type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	// OutputSchema when declared lets agents plan result parsing.
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
	// Risk is the static risk floor label (low|medium|high|critical).
	Risk    string   `json:"risk"`
	Effects []string `json:"effects,omitempty"`
	// ApprovalRequired is true when every call needs an approval token.
	ApprovalRequired bool `json:"approval_required,omitempty"`
	// ApprovalMinRisk when non-empty means risk at/above this level triggers approval.
	ApprovalMinRisk string `json:"approval_min_risk,omitempty"`
	// IdempotencyRequired is true when callers must supply an idempotency key.
	IdempotencyRequired bool `json:"idempotency_required,omitempty"`
	// SensitiveFieldsPresent flags that some output fields are redacted unless granted.
	SensitiveFieldsPresent bool `json:"sensitive_fields_present,omitempty"`
}

// SpecOf converts one operation into its tool spec. Pure; reads op only.
func SpecOf(op *core.Operation) ToolSpec {
	if op == nil {
		return ToolSpec{}
	}
	spec := ToolSpec{
		Name:        op.Name,
		Description: op.Description,
		Risk:        op.Risk.String(),
	}
	if len(op.InputSchema) > 0 {
		spec.InputSchema = append(json.RawMessage(nil), op.InputSchema...)
	}
	if len(op.OutputSchema) > 0 {
		spec.OutputSchema = append(json.RawMessage(nil), op.OutputSchema...)
	}
	for _, e := range op.Effects {
		spec.Effects = append(spec.Effects, string(e))
	}
	spec.ApprovalRequired = op.Approval.Required
	if op.Approval.MinRisk > core.RiskLow {
		spec.ApprovalMinRisk = op.Approval.MinRisk.String()
	}
	spec.IdempotencyRequired = op.Idempotency.Required
	spec.SensitiveFieldsPresent = len(op.SensitiveFields) > 0
	return spec
}

// Build returns specs for all registered operations passing include,
// sorted by name for deterministic output. A nil include hides everything
// (fail closed: discovery is opt-in, not ambient).
func Build(reg *core.Registry, include func(op *core.Operation) bool) []ToolSpec {
	if reg == nil || include == nil {
		return nil
	}
	names := reg.Names()
	sort.Strings(names)
	out := make([]ToolSpec, 0, len(names))
	for _, n := range names {
		op, err := reg.Get(n)
		if err != nil {
			continue
		}
		if !include(op) {
			continue
		}
		out = append(out, SpecOf(op))
	}
	return out
}

// ForCapabilities returns an include filter admitting operations whose
// required permissions are all covered by caps. Operations with no static
// permissions are hidden (they require explicit policy; visibility there
// would leak governance internals).
func ForCapabilities(caps []string) func(op *core.Operation) bool {
	held := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		held[c] = struct{}{}
	}
	return func(op *core.Operation) bool {
		if op == nil || len(op.Permissions) == 0 {
			return false
		}
		for _, p := range op.Permissions {
			if _, ok := held[p]; !ok {
				return false
			}
		}
		return true
	}
}

// AuthInfo describes how agents authenticate. Metadata only.
type AuthInfo struct {
	Schemes []string `json:"schemes"`
}

// Manifest is the static discovery document served at a well-known path.
// It contains no operation names and no per-caller data.
type Manifest struct {
	Service          string   `json:"service"`
	Version          string   `json:"version"`
	Description      string   `json:"description,omitempty"`
	ExecuteEndpoint  string   `json:"execute_endpoint"`
	CatalogOperation string   `json:"catalog_operation"`
	// MCPEndpoint is the JSON-RPC tools/* wire path when the HTTP edge exposes it.
	MCPEndpoint string `json:"mcp_endpoint,omitempty"`
	// OpenAPIEndpoint is the capability-filtered OpenAPI document path.
	OpenAPIEndpoint string `json:"openapi_endpoint,omitempty"`
	// GraphQLEndpoint is the GraphQL mutation execute path when enabled.
	GraphQLEndpoint string   `json:"graphql_endpoint,omitempty"`
	Auth            AuthInfo `json:"auth"`
}

// DefaultManifest returns the static discovery document for a Loom service.
func DefaultManifest(service string) Manifest {
	if service == "" {
		service = "loom"
	}
	return Manifest{
		Service:          service,
		Version:          "1",
		Description:      "Governed operation runtime: discover operations via the catalog operation, invoke via the execute endpoint.",
		ExecuteEndpoint:  "POST /v1/execute",
		CatalogOperation: "catalog.spec",
		Auth:             AuthInfo{Schemes: []string{"bearer", "mtls"}},
		MCPEndpoint:      "POST /mcp",
		OpenAPIEndpoint:  "GET /v1/openapi.json",
		GraphQLEndpoint:  "POST /graphql",
	}
}
