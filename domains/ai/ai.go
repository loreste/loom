// Package ai registers governed AI/tool operations with recursion limits.
package ai

import (
	"fmt"
	"strings"

	"github.com/loreste/loom/core"
)

const (
	OpComplete = "ai.complete"
	OpToolCall = "ai.tool_call"
)

// Register adds AI operations.
func Register(reg *core.Registry) error {
	if reg == nil {
		return fmt.Errorf("%w: nil registry", core.ErrInvalidArgument)
	}
	completeSchema := []byte(`{
		"type":"object",
		"properties":{
			"prompt":{"type":"string","minLength":1,"maxLength":8000},
			"depth":{"type":"integer","minimum":0,"maximum":3},
			"model":{"type":"string","maxLength":64}
		},
		"required":["prompt"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:        OpComplete,
		Description: "Run a model completion under AI guardrails",
		InputSchema: completeSchema,
		Permissions: []string{"ai.complete"},
		Risk:        core.RiskMedium,
		Effects:     []core.Effect{core.EffectAI, core.EffectRead},
		// Critical risk not default; approval when elevated by risk engine for agents
		Approval:    core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Idempotency: core.IdempotencyPolicy{Required: false},
		SensitiveFields: []string{"system_prompt", "tools_raw"},
	}, handleComplete); err != nil {
		return err
	}

	toolSchema := []byte(`{
		"type":"object",
		"properties":{
			"tool":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-z][a-z0-9_.]*$"},
			"arguments":{"type":"object"},
			"depth":{"type":"integer","minimum":0,"maximum":3}
		},
		"required":["tool"],
		"additionalProperties":false
	}`)
	return reg.Register(&core.Operation{
		Name:        OpToolCall,
		Description: "Invoke a tool on behalf of an agent (no privilege inheritance beyond policy)",
		InputSchema: toolSchema,
		Permissions: []string{"ai.tool_call"},
		Risk:        core.RiskHigh,
		Effects:     []core.Effect{core.EffectAI, core.EffectExec},
		Approval:    core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 300},
	}, handleToolCall)
}

func handleComplete(ec *core.ExecutionContext) (*core.Result, error) {
	prompt, _ := ec.Input["prompt"].(string)
	// Handler must still treat prompt as hostile — never execute it.
	summary := prompt
	if len(summary) > 80 {
		summary = summary[:80] + "…"
	}
	return &core.Result{
		Output: map[string]any{
			"completion_id": "cmp_" + ec.TraceID[:8],
			"echo_preview":  summary,
			"text":          "governed completion (stub)",
			// would be stripped if field not granted
			"system_prompt": "YOU SHOULD NEVER SEE THIS",
		},
	}, nil
}

func handleToolCall(ec *core.ExecutionContext) (*core.Result, error) {
	tool, _ := ec.Input["tool"].(string)
	// Deny dangerous tool names at handler as last line (defense in depth)
	blocked := []string{"shell.exec", "fs.delete", "iam.escalate", "network.raw"}
	for _, b := range blocked {
		if strings.EqualFold(tool, b) {
			return nil, fmt.Errorf("tool %q is blocked", tool)
		}
	}
	return &core.Result{
		Output: map[string]any{
			"tool_call_id": "tc_" + ec.TraceID[:8],
			"tool":         tool,
			"status":       "accepted",
		},
	}, nil
}
