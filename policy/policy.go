// Package policy is the permission and contextual policy engine.
// Default decision is DENY. Evaluation errors are DENY.
package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/loreste/loom/core"
)

// Decision is a policy result with reason.
type Decision struct {
	Decision core.Decision
	Reason   string
	Message  string
}

// Deny constructs an explicit deny.
func Deny(reason, message string) Decision {
	return Decision{Decision: core.DecisionDeny, Reason: reason, Message: message}
}

// Allow constructs an explicit allow. Must be intentional.
func Allow(message string) Decision {
	return Decision{Decision: core.DecisionAllow, Reason: "allow", Message: message}
}

// Engine evaluates operation and contextual policy.
type Engine interface {
	// CheckOperationPermission: does identity have required op permissions?
	CheckOperationPermission(ctx context.Context, id core.Identity, op *core.Operation) Decision
	// EvaluateContextual: additional CEL-like / rule checks. Fail → deny.
	EvaluateContextual(ctx context.Context, id core.Identity, boundary core.BoundaryID, op *core.Operation, req *core.Request) Decision
}

// Rule is an explicit allow rule. No matching rule ⇒ deny.
type Rule struct {
	// Principal exact match; empty = any (still need other matchers).
	Principal core.PrincipalID
	// Boundary exact; empty = any boundary (dangerous; prefer explicit).
	Boundary core.BoundaryID
	// Operation exact name or "*".
	Operation string
	// Permissions: identity must hold ALL of these (AND). Empty = rely on Operation match only.
	Permissions []string
	// EffectAllow lists effects this rule covers; empty = no effect restriction.
	EffectAllow []core.Effect
	// Deny overrides: if true, matching this rule forces deny (explicit deny wins).
	Deny bool
	// Priority: higher wins among matches; explicit Deny always beats Allow at same priority.
	Priority int
}

// MemoryEngine is an explicit-grant policy store with deny-overrides.
type MemoryEngine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewMemoryEngine returns a deny-all engine.
func NewMemoryEngine() *MemoryEngine {
	return &MemoryEngine{}
}

// AddRule appends a rule. Operation required.
func (e *MemoryEngine) AddRule(rule Rule) error {
	if e == nil {
		return fmt.Errorf("%w: nil engine", core.ErrInvalidArgument)
	}
	cp, err := normalizeRule(rule)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, cp)
	return nil
}

// ReplaceRules atomically replaces all rules (distributed policy apply).
// Empty slice is allowed (deny-all). Invalid rules fail closed without mutating.
func (e *MemoryEngine) ReplaceRules(rules []Rule) error {
	if e == nil {
		return fmt.Errorf("%w: nil engine", core.ErrInvalidArgument)
	}
	next := make([]Rule, 0, len(rules))
	for _, r := range rules {
		cp, err := normalizeRule(r)
		if err != nil {
			return err
		}
		next = append(next, cp)
	}
	e.mu.Lock()
	e.rules = next
	e.mu.Unlock()
	return nil
}

// Snapshot returns a copy of current rules.
func (e *MemoryEngine) Snapshot() []Rule {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	for i := range e.rules {
		out[i] = copyRule(e.rules[i])
	}
	return out
}

// RuleCount returns the number of loaded rules.
func (e *MemoryEngine) RuleCount() int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func normalizeRule(rule Rule) (Rule, error) {
	if rule.Operation == "" {
		return Rule{}, fmt.Errorf("%w: operation required", core.ErrInvalidArgument)
	}
	return copyRule(rule), nil
}

func copyRule(rule Rule) Rule {
	cp := rule
	cp.Permissions = append([]string(nil), rule.Permissions...)
	cp.EffectAllow = append([]core.Effect(nil), rule.EffectAllow...)
	return cp
}

// CheckOperationPermission verifies static op.Permissions against identity capabilities
// and explicit allow rules.
func (e *MemoryEngine) CheckOperationPermission(ctx context.Context, id core.Identity, op *core.Operation) Decision {
	if err := ctx.Err(); err != nil {
		return Deny(core.ReasonContextCanceled, err.Error())
	}
	if e == nil || op == nil {
		return Deny(core.ReasonPolicyError, "policy engine or operation missing")
	}

	// Capability check: identity must hold every permission listed on the operation.
	// Empty op.Permissions still requires an allow rule (no implicit allow).
	caps := capSet(id.Capabilities)
	for _, p := range op.Permissions {
		if !hasCap(caps, p) {
			return Deny(core.ReasonOperationDenied, fmt.Sprintf("missing capability %q", p))
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	var (
		bestAllow *Rule
		bestDeny  *Rule
	)
	// This phase is boundary-agnostic by design: boundary enforcement lives in
	// EvaluateContextual. Here only principal, operation, permissions, and
	// effects are matched.
	for i := range e.rules {
		rule := &e.rules[i]
		if rule.Principal != "" && rule.Principal != id.ID {
			continue
		}
		if rule.Operation != "*" && rule.Operation != op.Name {
			continue
		}
		// Permission AND on rule
		if len(rule.Permissions) > 0 {
			ok := true
			for _, p := range rule.Permissions {
				if !hasCap(caps, p) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		// Effect coverage: if rule lists EffectAllow, op effects must be subset.
		if len(rule.EffectAllow) > 0 && !effectsCovered(rule.EffectAllow, op.Effects) {
			continue
		}
		if rule.Deny {
			if bestDeny == nil || rule.Priority >= bestDeny.Priority {
				bestDeny = rule
			}
			continue
		}
		if bestAllow == nil || rule.Priority > bestAllow.Priority {
			bestAllow = rule
		}
	}

	// Explicit deny wins over allow when priority >= allow priority.
	if bestDeny != nil {
		if bestAllow == nil || bestDeny.Priority >= bestAllow.Priority {
			return Deny(core.ReasonPolicyDeny, "explicit deny rule matched")
		}
	}
	if bestAllow != nil {
		return Allow("operation rule matched")
	}
	// No rule matched → DENY (even if capabilities matched op.Permissions).
	// Capabilities are necessary but not sufficient without an allow rule.
	return Deny(core.ReasonOperationDenied, "no allow rule for operation")
}

// EvaluateContextual applies boundary-scoped rules and request metadata constraints.
func (e *MemoryEngine) EvaluateContextual(ctx context.Context, id core.Identity, boundary core.BoundaryID, op *core.Operation, req *core.Request) Decision {
	if err := ctx.Err(); err != nil {
		return Deny(core.ReasonContextCanceled, err.Error())
	}
	if e == nil || op == nil || req == nil {
		return Deny(core.ReasonPolicyError, "policy contextual inputs missing")
	}
	if boundary == "" {
		return Deny(core.ReasonBoundaryViolation, "empty boundary in contextual policy")
	}

	// Block obviously hostile metadata patterns (adapter baggage is untrusted).
	// Keys are matched case-insensitively; ANY non-empty value denies.
	if req.Metadata != nil {
		for k, v := range req.Metadata {
			if v == "" {
				continue
			}
			switch strings.ToLower(k) {
			case "x-loom-bypass", "x-admin-override":
				return Deny(core.ReasonPolicyDeny, "bypass header forbidden")
			}
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	var (
		bestAllow *Rule
		bestDeny  *Rule
	)
	caps := capSet(id.Capabilities)
	for i := range e.rules {
		rule := &e.rules[i]
		if rule.Principal != "" && rule.Principal != id.ID {
			continue
		}
		// Boundary == "" on a rule matches any boundary, but only via the
		// normal predicates (principal, operation, permissions, effect) below.
		if rule.Boundary != "" && rule.Boundary != boundary {
			continue
		}
		if rule.Operation != "*" && rule.Operation != op.Name {
			continue
		}
		if len(rule.Permissions) > 0 {
			ok := true
			for _, p := range rule.Permissions {
				if !hasCap(caps, p) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		if rule.Deny {
			if bestDeny == nil || rule.Priority >= bestDeny.Priority {
				bestDeny = rule
			}
			continue
		}
		if bestAllow == nil || rule.Priority > bestAllow.Priority {
			bestAllow = rule
		}
	}

	if bestDeny != nil {
		if bestAllow == nil || bestDeny.Priority >= bestAllow.Priority {
			return Deny(core.ReasonPolicyDeny, "explicit contextual deny")
		}
	}
	if bestAllow != nil {
		return Allow("contextual allow")
	}
	// No matching allow rule (global Boundary == "" rules already matched
	// above through the normal predicates) → DENY.
	return Deny(core.ReasonPolicyDeny, "no contextual allow rule")
}

func capSet(caps []string) map[string]struct{} {
	m := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		m[strings.ToLower(strings.TrimSpace(c))] = struct{}{}
	}
	return m
}

func hasCap(set map[string]struct{}, p string) bool {
	_, ok := set[strings.ToLower(strings.TrimSpace(p))]
	return ok
}

func effectsCovered(allowed []core.Effect, needed []core.Effect) bool {
	if len(needed) == 0 {
		return true
	}
	set := make(map[core.Effect]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	for _, n := range needed {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}
