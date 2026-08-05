// Package risk evaluates runtime risk. Risk may be raised above the operation static floor;
// it is never silently lowered below that floor.
package risk

import (
	"context"
	"strings"

	"github.com/loreste/loom/core"
)

// Engine computes risk for a request.
type Engine interface {
	Evaluate(ctx context.Context, id core.Identity, op *core.Operation, req *core.Request) core.RiskLevel
}

// Thresholds maps risk levels to whether execution may proceed without approval.
// Policy for blocking is owned by approval package; risk only scores.
type SimpleEngine struct {
	// RaiseOnMetadata keys that bump risk when present.
	RaiseOnMetadata []string
}

// NewSimpleEngine returns a default risk engine.
func NewSimpleEngine() *SimpleEngine {
	return &SimpleEngine{
		RaiseOnMetadata: []string{"x-forwarded-for", "x-danger", "batch"},
	}
}

// Evaluate starts at op.Risk and may raise.
func (e *SimpleEngine) Evaluate(_ context.Context, id core.Identity, op *core.Operation, req *core.Request) core.RiskLevel {
	if op == nil {
		return core.RiskCritical // fail closed
	}
	level := op.Risk

	// Money always at least high
	if op.HasEffect(core.EffectMoney) && level < core.RiskHigh {
		level = core.RiskHigh
	}
	// Admin/exec at least high
	if (op.HasEffect(core.EffectAdmin) || op.HasEffect(core.EffectExec)) && level < core.RiskHigh {
		level = core.RiskHigh
	}
	// Delete in prod-like boundary
	if op.HasEffect(core.EffectDelete) && (req.Boundary == "prod" || req.Boundary == "production") {
		level = maxRisk(level, core.RiskCritical)
	}
	// Delegated identity raises one notch
	if id.Delegator != "" {
		level = raise(level)
	}
	// Agent type raises
	if strings.EqualFold(id.Type, "agent") || strings.EqualFold(id.Type, "ai") {
		level = raise(level)
	}
	// Metadata signals
	if e != nil && req.Metadata != nil {
		for _, k := range e.RaiseOnMetadata {
			if _, ok := req.Metadata[k]; ok {
				level = raise(level)
				break
			}
		}
	}
	// Large batch sizes
	if n, ok := asInt(req.Input["count"]); ok && n > 100 {
		level = raise(level)
	}
	if n, ok := asInt(req.Input["amount"]); ok && n > 1000 {
		level = maxRisk(level, core.RiskHigh)
	}
	return level
}

func raise(r core.RiskLevel) core.RiskLevel {
	if r >= core.RiskCritical {
		return core.RiskCritical
	}
	return r + 1
}

func maxRisk(a, b core.RiskLevel) core.RiskLevel {
	if a > b {
		return a
	}
	return b
}

func asInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		return int64(t), true
	default:
		return 0, false
	}
}

// Blocker can force-deny based on risk alone (optional separate from approval).
type Blocker struct {
	// MaxAllowed risk; above this without special capability → block.
	MaxAllowed core.RiskLevel
	// BreakGlassCapability if held, allows up to critical (still audited).
	BreakGlassCapability string
}

// Check returns deny decision message if blocked; empty string if ok.
func (b *Blocker) Check(id core.Identity, level core.RiskLevel) string {
	if b == nil {
		return ""
	}
	max := b.MaxAllowed
	if b.BreakGlassCapability != "" {
		for _, c := range id.Capabilities {
			if c == b.BreakGlassCapability {
				return "" // break-glass still subject to approval package
			}
		}
	}
	if level > max {
		return "risk level exceeds maximum allowed"
	}
	return ""
}
