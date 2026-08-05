// Package deployment registers governed release operations.
package deployment

import (
	"fmt"
	"strings"

	"github.com/loreste/loom/core"
)

const (
	OpRelease = "deployment.release"
	OpRestart = "server.restart"
	OpDestroy = "server.destroy"
)

// Register adds deployment/server operations.
func Register(reg *core.Registry) error {
	if reg == nil {
		return fmt.Errorf("%w: nil registry", core.ErrInvalidArgument)
	}
	releaseSchema := []byte(`{
		"type":"object",
		"properties":{
			"service":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-z][a-z0-9-]*$"},
			"version":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-zA-Z0-9._-]+$"},
			"strategy":{"type":"string","pattern":"^(rolling|canary|bluegreen)$"}
		},
		"required":["service","version"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:        OpRelease,
		Description: "Release a service version",
		InputSchema: releaseSchema,
		Permissions: []string{"deployment.release"},
		Resources:   []string{"service"},
		Risk:        core.RiskHigh,
		Effects:     []core.Effect{core.EffectWrite, core.EffectExec},
		Approval:    core.ApprovalPolicy{MinRisk: core.RiskHigh, Effects: []core.Effect{core.EffectExec}},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
		Quota:       core.QuotaPolicy{Enabled: true},
	}, handleRelease); err != nil {
		return err
	}

	restartSchema := []byte(`{
		"type":"object",
		"properties":{
			"server_id":{"type":"string","minLength":1,"maxLength":64}
		},
		"required":["server_id"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:        OpRestart,
		Description: "Restart a server",
		InputSchema: restartSchema,
		Permissions: []string{"server.restart"},
		Resources:   []string{"server"},
		Risk:        core.RiskHigh,
		Effects:     []core.Effect{core.EffectExec},
		Approval:    core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 600},
		Quota:       core.QuotaPolicy{Enabled: true},
	}, handleRestart); err != nil {
		return err
	}

	return reg.Register(&core.Operation{
		Name:        OpDestroy,
		Description: "Destroy a server (blocked in production by guardrail)",
		InputSchema: restartSchema,
		Permissions: []string{"server.destroy"},
		Resources:   []string{"server"},
		Risk:        core.RiskCritical,
		Effects:     []core.Effect{core.EffectDelete, core.EffectAdmin, core.EffectExec},
		Approval:    core.ApprovalPolicy{Required: true},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
		Quota:       core.QuotaPolicy{Enabled: true},
	}, handleDestroy)
}

func handleRelease(ec *core.ExecutionContext) (*core.Result, error) {
	svc, _ := ec.Input["service"].(string)
	ver, _ := ec.Input["version"].(string)
	strategy, _ := ec.Input["strategy"].(string)
	if strategy == "" {
		strategy = "rolling"
	}
	// Block obviously hostile version tags even if schema passed
	if strings.Contains(ver, "..") || strings.Contains(ver, "/") {
		return nil, fmt.Errorf("invalid version")
	}
	return &core.Result{
		Output: map[string]any{
			"release_id": "rel_" + ec.TraceID[:8],
			"service":    svc,
			"version":    ver,
			"strategy":   strategy,
			"status":     "released",
			"boundary":   string(ec.Boundary),
		},
	}, nil
}

func handleRestart(ec *core.ExecutionContext) (*core.Result, error) {
	sid, _ := ec.Input["server_id"].(string)
	return &core.Result{
		Output: map[string]any{
			"server_id": sid,
			"status":    "restarted",
		},
	}, nil
}

func handleDestroy(ec *core.ExecutionContext) (*core.Result, error) {
	sid, _ := ec.Input["server_id"].(string)
	return &core.Result{
		Output: map[string]any{
			"server_id": sid,
			"status":    "destroyed",
		},
	}, nil
}
