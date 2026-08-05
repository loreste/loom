// Package admin registers privileged governance operations.
// These still go through the full runtime pipeline — never HTTP shortcuts.
package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/catalog"
	"github.com/loreste/loom/core"
)

const (
	OpApprovalIssue = "approval.issue"
	OpCatalogList   = "catalog.list"
	OpCatalogSpec   = "catalog.spec"
)

// Deps for admin handlers.
type Deps struct {
	Approvals approval.Issuer
	Registry  *core.Registry
}

// Register wires admin operations.
func Register(reg *core.Registry, deps Deps) error {
	if reg == nil || deps.Approvals == nil {
		return fmt.Errorf("%w: registry and approvals required", core.ErrInvalidArgument)
	}
	issueSchema := []byte(`{
		"type":"object",
		"properties":{
			"token":{"type":"string","minLength":8,"maxLength":128},
			"principal":{"type":"string","minLength":1,"maxLength":128},
			"operation":{"type":"string","minLength":1,"maxLength":128},
			"boundary":{"type":"string","minLength":1,"maxLength":64},
			"ttl_seconds":{"type":"integer","minimum":60,"maximum":86400},
			"max_risk":{"type":"string","pattern":"^(low|medium|high|critical)$"},
			"generate_token":{"type":"boolean"}
		},
		"required":["principal","operation","boundary"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:        OpApprovalIssue,
		Description: "Issue a single-use approval token for another principal/operation",
		InputSchema: issueSchema,
		Permissions: []string{"approval.issue"},
		Risk:        core.RiskHigh,
		Effects:     []core.Effect{core.EffectAdmin, core.EffectWrite},
		// Issuing approvals is itself high risk — require approval for critical chains,
		// but MinRisk high means issuers need prior approval when risk elevates.
		// Static Required=false so bootstrap admin can issue with capability+policy only
		// unless risk engine raises to critical.
		Approval: core.ApprovalPolicy{MinRisk: core.RiskCritical},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
		SensitiveFields: []string{"token"},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleIssue(ec, deps.Approvals)
	}); err != nil {
		return err
	}

	listSchema := []byte(`{"type":"object","properties":{},"additionalProperties":false}`)
	if err := reg.Register(&core.Operation{
		Name:        OpCatalogList,
		Description: "List registered operation names (no schemas leaked by default)",
		InputSchema: listSchema,
		Permissions: []string{"catalog.list"},
		Risk:        core.RiskLow,
		Effects:     []core.Effect{core.EffectRead},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		if deps.Registry == nil {
			return nil, fmt.Errorf("registry not configured")
		}
		names := deps.Registry.Names()
		// sort for stability
		out := make([]any, len(names))
		for i, n := range names {
			out[i] = n
		}
		return &core.Result{Output: map[string]any{
			"operations": out,
			"count":      len(names),
		}}, nil
	}); err != nil {
		return err
	}

	// catalog.spec exposes full agent-facing tool specs, filtered to the
	// caller's capabilities: agents only ever see operations they could
	// actually be granted. Ops without static permissions stay hidden.
	return reg.Register(&core.Operation{
		Name:        OpCatalogSpec,
		Description: "Describe operations callable by the caller (schemas, risk, approval, idempotency)",
		InputSchema: listSchema,
		Permissions: []string{"catalog.spec"},
		Risk:        core.RiskLow,
		Effects:     []core.Effect{core.EffectRead},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		if deps.Registry == nil {
			return nil, fmt.Errorf("registry not configured")
		}
		specs := catalog.Build(deps.Registry, catalog.ForCapabilities(ec.Identity.Capabilities))
		// Normalize to JSON-shaped values so every adapter and in-process
		// callers see the same wire form.
		raw, err := json.Marshal(specs)
		if err != nil {
			return nil, err
		}
		var out []any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		if out == nil {
			out = []any{}
		}
		return &core.Result{Output: map[string]any{
			"tools": out,
			"count": len(specs),
		}}, nil
	})
}

func handleIssue(ec *core.ExecutionContext, iss approval.Issuer) (*core.Result, error) {
	principal, _ := ec.Input["principal"].(string)
	operation, _ := ec.Input["operation"].(string)
	boundary, _ := ec.Input["boundary"].(string)
	// Adversarial: issuer cannot mint approvals for ops they could not themselves
	// be granted — still enforced by policy who may call approval.issue.
	// Cannot issue for approval.issue recursively to amplify (optional hard block).
	if operation == OpApprovalIssue {
		return nil, fmt.Errorf("cannot issue approval for approval.issue")
	}

	token, _ := ec.Input["token"].(string)
	gen, _ := ec.Input["generate_token"].(bool)
	if gen || token == "" {
		t, err := randomToken(24)
		if err != nil {
			return nil, err
		}
		token = t
	}
	if len(token) < 8 {
		return nil, fmt.Errorf("token too short")
	}

	ttlSec := 3600.0
	if v, ok := ec.Input["ttl_seconds"].(float64); ok && v >= 60 {
		ttlSec = v
	}
	maxRisk := core.RiskCritical
	if s, ok := ec.Input["max_risk"].(string); ok && s != "" {
		maxRisk = core.ParseRiskLevel(s)
	}

	if err := iss.Issue(token, core.PrincipalID(principal), operation, core.BoundaryID(boundary), maxRisk, time.Duration(ttlSec)*time.Second); err != nil {
		return nil, err
	}

	// Return token once — field filter may strip "token" unless granted.
	// Admins must have field grant for token to receive it.
	return &core.Result{
		Output: map[string]any{
			"status":    "issued",
			"token":     token,
			"principal": principal,
			"operation": operation,
			"boundary":  boundary,
			"ttl_seconds": int64(ttlSec),
			"max_risk":  maxRisk.String(),
			"issued_by": string(ec.Identity.ID),
		},
	}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
