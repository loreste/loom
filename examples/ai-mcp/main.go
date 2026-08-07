// Command ai-mcp demonstrates an AI/MCP tool surface whose every invocation
// is translated into Loom's governed runtime. Tool discovery is metadata only;
// approval, capability, schema, risk, quota, and output filtering remain in
// the runtime.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/domains/ai"
)

const (
	principal = core.PrincipalID("svc:assistant")
	boundary  = core.BoundaryID("tenant-a")
)

func newAssistant() (*app.App, string, error) {
	a, err := app.New(app.Config{})
	if err != nil {
		return nil, "", err
	}
	if err := ai.Register(a.Registry); err != nil {
		_ = a.Close()
		return nil, "", err
	}
	token := os.Getenv("LOOM_AI_TOKEN")
	if token == "" {
		token = "local-ai-token"
	}
	if err := a.AddUser(principal, token, boundary, []string{"ai.complete", "ai.tool_call"}); err != nil {
		_ = a.Close()
		return nil, "", err
	}
	if err := a.GrantOp(principal, boundary, ai.OpComplete, "", "", []string{"completion_id", "text", "echo_preview"}); err != nil {
		_ = a.Close()
		return nil, "", err
	}
	if err := a.GrantOp(principal, boundary, ai.OpToolCall, "", "", []string{"tool_call_id", "tool", "status"}); err != nil {
		_ = a.Close()
		return nil, "", err
	}
	return a, token, nil
}

func main() {
	a, token, err := newAssistant()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer a.Close()
	if err := a.IssueApproval("ai-demo-approval", principal, ai.OpToolCall, boundary, core.RiskHigh, time.Hour); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	adapter := mcp.New(a.Runtime)
	response, err := adapter.Call(context.Background(), mcp.ToolCall{
		Name:           "ai.tool_call",
		Arguments:      map[string]any{"tool": "calendar.lookup", "arguments": map[string]any{"day": "today"}},
		BearerToken:    token,
		Boundary:       string(boundary),
		IdempotencyKey: "ai-demo-1",
		ApprovalToken:  "ai-demo-approval",
		Fields:         []string{"tool", "status"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, _ := json.MarshalIndent(response, "", "  ")
	fmt.Println(string(encoded))
}
