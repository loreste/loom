package main

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/core"
)

func TestToolCallUsesGovernedRuntimeAndConstrainedOutput(t *testing.T) {
	a, token, err := newAssistant()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.IssueApproval("approval-1", principal, "ai.tool_call", boundary, core.RiskHigh, time.Hour); err != nil {
		t.Fatal(err)
	}
	response, err := mcp.New(a.Runtime).Call(context.Background(), mcp.ToolCall{
		Name:           "ai.tool_call",
		Arguments:      map[string]any{"tool": "calendar.lookup"},
		BearerToken:    token,
		Boundary:       string(boundary),
		IdempotencyKey: "test-tool-1",
		ApprovalToken:  "approval-1",
		Fields:         []string{"tool", "status"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !response.Allowed {
		t.Fatalf("tool call denied: %+v", response.Denial)
	}
	if _, ok := response.Output["arguments"]; ok {
		t.Fatal("unrestricted tool arguments leaked through MCP output")
	}
}

func TestToolDiscoveryDoesNotGrantAccess(t *testing.T) {
	a, _, err := newAssistant()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	names := mcp.ListTools(a.Registry, "loom.")
	if len(names) == 0 {
		t.Fatal("expected discovered tool metadata")
	}
	response, err := mcp.New(a.Runtime).Call(context.Background(), mcp.ToolCall{
		Name:        "ai.tool_call",
		Arguments:   map[string]any{"tool": "calendar.lookup"},
		BearerToken: "unknown-token",
		Boundary:    string(boundary),
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Allowed {
		t.Fatal("discovery must not grant invocation access")
	}
}
