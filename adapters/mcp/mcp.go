// Package mcp adapts MCP tool calls into Loom.
// Core does not import this package. MCP cannot bypass Runtime.Execute.
package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

// ToolCall is an MCP-shaped invocation (transport-agnostic).
type ToolCall struct {
	Name           string
	Arguments      map[string]any
	BearerToken    string
	Boundary       string
	IdempotencyKey string
	ApprovalToken  string
	Resource       *core.ResourceRef
	Fields         []string
	// SessionID / ClientID are metadata only.
	SessionID string
	ClientID  string
}

// Adapter translates tool calls into Loom requests.
type Adapter struct {
	RT *runtime.Runtime
	// NamePrefix optional prefix stripped from tool names (e.g. "loom.").
	NamePrefix string
	// AllowedTools if non-empty, pre-filters tool names (runtime still enforces).
	AllowedTools map[string]struct{}
}

// New creates an MCP adapter.
func New(rt *runtime.Runtime) *Adapter {
	return &Adapter{RT: rt}
}

// Call executes a tool through the runtime. There is no privileged path.
func (a *Adapter) Call(ctx context.Context, call ToolCall) (core.Response, error) {
	if a == nil || a.RT == nil {
		return core.Response{}, fmt.Errorf("mcp: runtime not configured")
	}
	name := call.Name
	if a.NamePrefix != "" && strings.HasPrefix(name, a.NamePrefix) {
		name = strings.TrimPrefix(name, a.NamePrefix)
	}
	if a.AllowedTools != nil {
		if _, ok := a.AllowedTools[name]; !ok {
			return core.Response{
				Allowed:  false,
				Decision: core.DecisionDeny,
				Denial:   core.NewDenial("mcp", core.ReasonOperationDenied, "tool not in MCP allowlist", nil),
			}, nil
		}
	}
	req := core.Request{
		Operation: name,
		Credentials: core.Credentials{
			Scheme: "bearer",
			Token:  call.BearerToken,
		},
		Boundary:       core.BoundaryID(call.Boundary),
		Resource:       call.Resource,
		Input:          call.Arguments,
		Fields:         call.Fields,
		IdempotencyKey: call.IdempotencyKey,
		ApprovalToken:  call.ApprovalToken,
		Metadata: map[string]string{
			"adapter":    "mcp",
			"session_id": call.SessionID,
			"client_id":  call.ClientID,
		},
	}
	return a.RT.Execute(ctx, req), nil
}

// ListTools returns registered operations as MCP tool names (metadata only).
// Does not grant invoke rights.
func ListTools(reg *core.Registry, prefix string) []string {
	if reg == nil {
		return nil
	}
	names := reg.Names()
	if prefix == "" {
		return names
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = prefix + n
	}
	return out
}
