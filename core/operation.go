package core

import "encoding/json"

// Effect classifies side-effects. Used by risk, audit, and approval policy.
type Effect string

const (
	EffectRead   Effect = "read"
	EffectWrite  Effect = "write"
	EffectDelete Effect = "delete"
	EffectExec   Effect = "exec"
	EffectMoney  Effect = "money"
	EffectAdmin  Effect = "admin"
	// EffectAI marks model/tool recursion surfaces.
	EffectAI Effect = "ai"
)

// RiskLevel is an operation's static risk ceiling. Runtime may raise, never lower silently.
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes risk as a string label.
func (r RiskLevel) MarshalJSON() ([]byte, error) {
	return []byte(`"` + r.String() + `"`), nil
}

// UnmarshalJSON fails closed to RiskCritical on unknown labels.
func (r *RiskLevel) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		*r = RiskCritical
		return nil
	}
	*r = ParseRiskLevel(s)
	return nil
}

// ParseRiskLevel fails closed: unknown → RiskCritical (not low).
func ParseRiskLevel(s string) RiskLevel {
	switch s {
	case "low":
		return RiskLow
	case "medium":
		return RiskMedium
	case "high":
		return RiskHigh
	case "critical":
		return RiskCritical
	default:
		return RiskCritical
	}
}

// IdempotencyPolicy controls replay behavior for an operation.
type IdempotencyPolicy struct {
	// Required forces clients to supply an idempotency key.
	Required bool
	// TTLSeconds is how long results are retained. 0 = runtime default.
	TTLSeconds int
}

// ApprovalPolicy gates execution for elevated risk or effect classes.
type ApprovalPolicy struct {
	// Required forces an approval token or pending approval for every call.
	Required bool
	// MinRisk triggers approval when runtime risk >= this level.
	MinRisk RiskLevel
	// Effects that always require approval when present.
	Effects []Effect
}

// Operation is the universal callable unit. Unknown operations do not exist → deny.
type Operation struct {
	// Name is dotted, e.g. "document.read", "payment.capture".
	Name string

	// Description is human-facing only; never used for authz.
	Description string

	// InputSchema / OutputSchema are JSON Schema documents (optional but recommended).
	// When set, guardrails enforce them fail-closed.
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage

	// Permissions are the capability names required to invoke this op.
	// Empty means no static grant path: only explicit policy can allow (still default deny).
	Permissions []string

	// Resources describes resource-type constraints (type prefixes / patterns).
	Resources []string

	// Risk is the static floor for risk evaluation.
	Risk RiskLevel

	// Effects list side-effect classes.
	Effects []Effect

	// Limits are soft metadata; quotas package enforces hard limits.
	Limits map[string]int64

	Approval    ApprovalPolicy
	Idempotency IdempotencyPolicy

	// SensitiveFields are redacted from audit/output unless explicitly permitted.
	SensitiveFields []string
}

// HasEffect reports whether op declares e.
func (o *Operation) HasEffect(e Effect) bool {
	if o == nil {
		return false
	}
	for _, x := range o.Effects {
		if x == e {
			return true
		}
	}
	return false
}
