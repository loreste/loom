// Package graphql adapts GraphQL to Loom. It never bypasses the runtime.
//
// Surface:
//   - query health: static "ok"
//   - mutation execute: maps to Runtime.Execute
//
// Auth: HTTP Authorization bearer is read from the request context
// (see WithHTTPRequest / Handler). Bypass headers are recorded as metadata
// tripwires only.
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/graphql-go/graphql"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

type ctxKey int

const (
	ctxHTTPRequest ctxKey = iota
	ctxToken
)

// WithToken stores a bearer token on the context (tests / non-HTTP).
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxToken, token)
}

// WithHTTPRequest attaches the inbound *http.Request for auth/metadata.
func WithHTTPRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, ctxHTTPRequest, r)
}

// Schema builds the Loom GraphQL schema bound to rt.
func Schema(rt *runtime.Runtime) (graphql.Schema, error) {
	if rt == nil {
		return graphql.Schema{}, fmt.Errorf("%w: runtime required", core.ErrInvalidArgument)
	}

	resourceInput := graphql.NewInputObject(graphql.InputObjectConfig{
		Name: "ResourceRefInput",
		Fields: graphql.InputObjectConfigFieldMap{
			"type": &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"id":   &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
		},
	})

	executeInput := graphql.NewInputObject(graphql.InputObjectConfig{
		Name: "ExecuteInput",
		Fields: graphql.InputObjectConfigFieldMap{
			"operation":       &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"boundary":        &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"input":           &graphql.InputObjectFieldConfig{Type: graphql.String, Description: "JSON object string"},
			"resource":        &graphql.InputObjectFieldConfig{Type: resourceInput},
			"fields":          &graphql.InputObjectFieldConfig{Type: graphql.NewList(graphql.String)},
			"idempotencyKey":  &graphql.InputObjectFieldConfig{Type: graphql.String},
			"approvalToken":   &graphql.InputObjectFieldConfig{Type: graphql.String},
			"traceId":         &graphql.InputObjectFieldConfig{Type: graphql.String},
		},
	})

	denialType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Denial",
		Fields: graphql.Fields{
			"reason":    &graphql.Field{Type: graphql.String},
			"message":   &graphql.Field{Type: graphql.String},
			"step":      &graphql.Field{Type: graphql.String},
			"retryable": &graphql.Field{Type: graphql.Boolean},
			"hint":      &graphql.Field{Type: graphql.String},
		},
	})

	resultType := graphql.NewObject(graphql.ObjectConfig{
		Name: "ExecuteResult",
		Fields: graphql.Fields{
			"allowed":          &graphql.Field{Type: graphql.Boolean},
			"decision":         &graphql.Field{Type: graphql.String},
			"output":           &graphql.Field{Type: graphql.String, Description: "JSON object string"},
			"denial":           &graphql.Field{Type: denialType},
			"traceId":          &graphql.Field{Type: graphql.String},
			"auditId":          &graphql.Field{Type: graphql.String},
			"idempotentReplay": &graphql.Field{Type: graphql.Boolean},
			"risk":             &graphql.Field{Type: graphql.String},
		},
	})

	rootQuery := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"health": &graphql.Field{
				Type: graphql.String,
				Resolve: func(_ graphql.ResolveParams) (any, error) {
					return "ok", nil
				},
			},
		},
	})

	rootMutation := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			"execute": &graphql.Field{
				Type: resultType,
				Args: graphql.FieldConfigArgument{
					"input": &graphql.ArgumentConfig{Type: graphql.NewNonNull(executeInput)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return resolveExecute(p, rt)
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{
		Query:    rootQuery,
		Mutation: rootMutation,
	})
}

func resolveExecute(p graphql.ResolveParams, rt *runtime.Runtime) (any, error) {
	raw, _ := p.Args["input"].(map[string]any)
	if raw == nil {
		return nil, fmt.Errorf("input required")
	}
	op, _ := raw["operation"].(string)
	boundary, _ := raw["boundary"].(string)
	if op == "" || boundary == "" {
		return nil, fmt.Errorf("operation and boundary required")
	}

	input := map[string]any{}
	if s, ok := raw["input"].(string); ok && strings.TrimSpace(s) != "" {
		if err := json.Unmarshal([]byte(s), &input); err != nil {
			return nil, fmt.Errorf("input must be a JSON object string")
		}
	}

	var fields []string
	if arr, ok := raw["fields"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				fields = append(fields, s)
			}
		}
	}

	req := core.Request{
		Operation:      op,
		Boundary:       core.BoundaryID(boundary),
		Input:          input,
		Fields:         fields,
		IdempotencyKey: strArg(raw, "idempotencyKey"),
		ApprovalToken:  strArg(raw, "approvalToken"),
		TraceID:        strArg(raw, "traceId"),
		Credentials: core.Credentials{
			Scheme: "bearer",
			Token:  tokenFrom(p.Context),
		},
		Metadata: metadataFrom(p.Context),
	}
	if res, ok := raw["resource"].(map[string]any); ok {
		req.Resource = &core.ResourceRef{
			Type: strArg(res, "type"),
			ID:   strArg(res, "id"),
		}
	}

	resp := rt.Execute(p.Context, req)
	return resultMap(resp), nil
}

func strArg(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func tokenFrom(ctx context.Context) string {
	if t, ok := ctx.Value(ctxToken).(string); ok && t != "" {
		return t
	}
	if r, ok := ctx.Value(ctxHTTPRequest).(*http.Request); ok && r != nil {
		return bearer(r.Header.Get("Authorization"))
	}
	return ""
}

func metadataFrom(ctx context.Context) map[string]string {
	md := map[string]string{"adapter": "graphql"}
	r, ok := ctx.Value(ctxHTTPRequest).(*http.Request)
	if !ok || r == nil {
		return md
	}
	if v := r.Header.Get("X-Loom-Bypass"); v != "" {
		md["x-loom-bypass"] = "1"
	}
	if v := r.Header.Get("X-Admin-Override"); v != "" {
		md["x-admin-override"] = "1"
	}
	md["remote_addr"] = r.RemoteAddr
	return md
}

func bearer(h string) string {
	const p = "Bearer "
	h = strings.TrimSpace(h)
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

func resultMap(resp core.Response) map[string]any {
	out := map[string]any{
		"allowed":          resp.Allowed,
		"decision":         resp.Decision.String(),
		"traceId":          resp.TraceID,
		"auditId":          resp.AuditID,
		"idempotentReplay": resp.IdempotentReplay,
		"risk":             resp.Risk.String(),
	}
	if resp.Output != nil {
		b, err := json.Marshal(resp.Output)
		if err == nil {
			out["output"] = string(b)
		}
	}
	if resp.Denial != nil {
		out["denial"] = map[string]any{
			"reason":    resp.Denial.Reason,
			"message":   resp.Denial.Message,
			"step":      resp.Denial.Step,
			"retryable": resp.Denial.Retryable,
			"hint":      resp.Denial.Hint,
		}
	}
	return out
}

// Handler serves GraphQL over HTTP (POST JSON body {query, variables}).
// Always goes through Runtime.Execute for mutations.
func Handler(rt *runtime.Runtime) (http.Handler, error) {
	schema, err := Schema(rt)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"errors":[{"message":"POST only"}]}`, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, `{"errors":[{"message":"read body"}]}`, http.StatusBadRequest)
			return
		}
		var payload struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || payload.Query == "" {
			http.Error(w, `{"errors":[{"message":"invalid graphql body"}]}`, http.StatusBadRequest)
			return
		}
		ctx := WithHTTPRequest(r.Context(), r)
		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  payload.Query,
			VariableValues: payload.Variables,
			Context:        ctx,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(w).Encode(result)
	}), nil
}

// Do executes a GraphQL request in-process (tests / embed).
func Do(ctx context.Context, rt *runtime.Runtime, query string, variables map[string]any) (*graphql.Result, error) {
	schema, err := Schema(rt)
	if err != nil {
		return nil, err
	}
	return graphql.Do(graphql.Params{
		Schema:         schema,
		RequestString:  query,
		VariableValues: variables,
		Context:        ctx,
	}), nil
}
