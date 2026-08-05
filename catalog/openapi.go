package catalog

import (
	"encoding/json"
	"sort"
)

// OpenAPIOptions tunes the OpenAPI document export.
type OpenAPIOptions struct {
	// Title defaults to service name.
	Title string
	// Version document version (default "1.0.0").
	Version string
	// Description optional.
	Description string
	// ServerURL optional base URL (e.g. "https://loom.example").
	ServerURL string
	// ExecutePath defaults to "/v1/execute".
	ExecutePath string
}

// OpenAPI builds a minimal OpenAPI 3.0.3 document from agent-facing tool specs.
//
// Each operation becomes a path POST /ops/{name} whose requestBody schema is the
// operation's input_schema. The document also documents the real execute surface
// (POST /v1/execute) and Loom-specific extensions (x-loom-*).
//
// Specs must already be capability-filtered by the caller — this function never
// grants invoke rights and does not consult policy.
func OpenAPI(service string, specs []ToolSpec, opts OpenAPIOptions) map[string]any {
	if service == "" {
		service = "loom"
	}
	title := opts.Title
	if title == "" {
		title = service
	}
	ver := opts.Version
	if ver == "" {
		ver = "1.0.0"
	}
	execPath := opts.ExecutePath
	if execPath == "" {
		execPath = "/v1/execute"
	}
	desc := opts.Description
	if desc == "" {
		desc = "Governed Loom operations. Paths under /ops/* describe tool schemas; " +
			"invoke via POST " + execPath + " (or MCP tools/call). Discovery never grants rights."
	}

	paths := map[string]any{}
	// Real execute endpoint — generic envelope.
	paths[execPath] = map[string]any{
		"post": map[string]any{
			"operationId": "loom_execute",
			"summary":     "Execute a governed operation",
			"description": "Single entrypoint. Body.operation selects the tool; policy is enforced server-side.",
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"requestBody": map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": executeEnvelopeSchema(),
					},
				},
			},
			"responses": map[string]any{
				"200": map[string]any{"description": "Allowed (or structured deny with allowed=false)"},
				"401": map[string]any{"description": "Unauthenticated"},
				"403": map[string]any{"description": "Denied by policy/guardrails"},
			},
		},
	}

	// Stable path order for deterministic JSON.
	names := make([]string, 0, len(specs))
	byName := make(map[string]ToolSpec, len(specs))
	for _, sp := range specs {
		if sp.Name == "" {
			continue
		}
		names = append(names, sp.Name)
		byName[sp.Name] = sp
	}
	sort.Strings(names)

	for _, name := range names {
		sp := byName[name]
		path := "/ops/" + name
		opID := openAPIOpID(name)
		schema := schemaOrObject(sp.InputSchema)
		post := map[string]any{
			"operationId": opID,
			"summary":     sp.Description,
			"description": sp.Description,
			"security":    []map[string][]string{{"bearerAuth": {}}},
			"requestBody": map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": schema,
					},
				},
			},
			"responses": map[string]any{
				"200": map[string]any{"description": "Governed result (invoke via " + execPath + ")"},
			},
			// Loom governance extensions — agents use these; they are not grants.
			"x-loom-operation":            sp.Name,
			"x-loom-risk":                 sp.Risk,
			"x-loom-effects":              sp.Effects,
			"x-loom-approval-required":    sp.ApprovalRequired,
			"x-loom-idempotency-required": sp.IdempotencyRequired,
			"x-loom-sensitive-fields":     sp.SensitiveFieldsPresent,
		}
		if sp.ApprovalMinRisk != "" {
			post["x-loom-approval-min-risk"] = sp.ApprovalMinRisk
		}
		if len(sp.OutputSchema) > 0 {
			if out := schemaOrObject(sp.OutputSchema); out != nil {
				post["responses"] = map[string]any{
					"200": map[string]any{
						"description": "Governed result",
						"content": map[string]any{
							"application/json": map[string]any{"schema": out},
						},
					},
				}
			}
		}
		paths[path] = map[string]any{"post": post}
	}

	doc := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       title,
			"version":     ver,
			"description": desc,
		},
		"paths": paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "token",
				},
			},
		},
		"security": []map[string][]string{{"bearerAuth": {}}},
		// Static discovery pointer (no op names).
		"x-loom-manifest":     "/.well-known/loom.json",
		"x-loom-catalog-op":   "catalog.spec",
		"x-loom-execute-path": execPath,
	}
	if opts.ServerURL != "" {
		doc["servers"] = []map[string]any{{"url": opts.ServerURL}}
	}
	return doc
}

func schemaOrObject(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{"type": "object"}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return map[string]any{"type": "object"}
	}
	return v
}

func executeEnvelopeSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"operation", "boundary"},
		"properties": map[string]any{
			"operation":       map[string]any{"type": "string", "description": "Registered operation name"},
			"boundary":        map[string]any{"type": "string"},
			"input":           map[string]any{"type": "object"},
			"resource":        map[string]any{"type": "object", "properties": map[string]any{"type": map[string]any{"type": "string"}, "id": map[string]any{"type": "string"}}},
			"idempotency_key": map[string]any{"type": "string"},
			"approval_token":  map[string]any{"type": "string"},
			"fields":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
}

func openAPIOpID(name string) string {
	// operationId must be alphanumeric + underscore for many generators.
	b := make([]byte, 0, len(name)+4)
	b = append(b, "op_"...)
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	return string(b)
}
