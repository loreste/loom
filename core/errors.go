// Package core defines Loom's universal execution model and fail-closed error taxonomy.
// Adapters, SDKs, and business logic must never invent privilege; they only carry claims.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Decision is the outcome of any enforcement step.
// Anything that is not ExplicitAllow is treated as deny.
type Decision int

// Outcome describes what the caller can safely rely on after execution.
// ExecutedUnconfirmed is distinct from deny: the handler may have produced a
// side effect, but post-execution recording did not complete.
type Outcome string

const (
	OutcomeDenied              Outcome = "denied"
	OutcomeAllowed             Outcome = "allowed"
	OutcomeExecutedUnconfirmed Outcome = "executed_unconfirmed"
)

func (o Outcome) String() string {
	if o == "" {
		return string(OutcomeDenied)
	}
	return string(o)
}

const (
	// DecisionDeny is the default. Zero value is deny (adversarial default).
	DecisionDeny Decision = iota
	// DecisionAllow is an explicit positive grant. Never implied.
	DecisionAllow
	// DecisionRequireApproval means execution is blocked pending human/system approval.
	DecisionRequireApproval
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionRequireApproval:
		return "require_approval"
	default:
		return "deny"
	}
}

// MarshalJSON encodes decision as a stable string (never trust numeric ordinals over the wire).
func (d Decision) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

// UnmarshalJSON fails closed: unknown values become DecisionDeny.
func (d *Decision) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// numeric legacy: anything other than explicit allow string → deny
		*d = DecisionDeny
		return nil
	}
	switch s {
	case "allow":
		*d = DecisionAllow
	case "require_approval":
		*d = DecisionRequireApproval
	default:
		*d = DecisionDeny
	}
	return nil
}

// Allowed returns true only for DecisionAllow.
func (d Decision) Allowed() bool { return d == DecisionAllow }

// Reason codes for deny/approval. Stable for audit and client mapping.
const (
	ReasonUnauthenticated     = "unauthenticated"
	ReasonInvalidDelegation   = "invalid_delegation"
	ReasonBoundaryViolation   = "boundary_violation"
	ReasonOperationDenied     = "operation_denied"
	ReasonResourceDenied      = "resource_denied"
	ReasonFieldDenied         = "field_denied"
	ReasonPolicyDeny          = "policy_deny"
	ReasonPolicyError         = "policy_error" // fail-closed: eval error == deny
	ReasonGuardrail           = "guardrail"
	ReasonRiskBlocked         = "risk_blocked"
	ReasonApprovalRequired    = "approval_required"
	ReasonApprovalDenied      = "approval_denied"
	ReasonQuotaExceeded       = "quota_exceeded"
	ReasonIdempotencyConflict = "idempotency_conflict"
	ReasonSchemaInvalid       = "schema_invalid"
	ReasonOperationUnknown    = "operation_unknown"
	ReasonHandlerMissing      = "handler_missing"
	ReasonExecutionFailed     = "execution_failed"
	ReasonOutputFilter        = "output_filter"
	ReasonInternal            = "internal"
	ReasonContextCanceled     = "context_canceled"
	ReasonExecutedUnconfirmed = "executed_unconfirmed"
)

// Denial is a structured, auditable rejection. It is never an "error to ignore".
type Denial struct {
	Reason  string
	Message string
	// Step is the pipeline stage that rejected (e.g. "authenticate", "guardrails").
	Step string
	// Retryable tells agents whether a retry (after the hinted action, or later)
	// can succeed. Static per reason, never derived from internal errors.
	Retryable bool
	// Hint is static, agent-actionable guidance keyed on Reason.
	// It never contains internal error text.
	Hint string
	// Details is non-sensitive diagnostic data only. Never put secrets here.
	Details map[string]string
}

func (d *Denial) Error() string {
	if d == nil {
		return "denied"
	}
	if d.Message != "" {
		return fmt.Sprintf("loom: deny [%s/%s]: %s", d.Step, d.Reason, d.Message)
	}
	return fmt.Sprintf("loom: deny [%s/%s]", d.Step, d.Reason)
}

// reasonInfo is the static, caller-safe description of a deny reason.
type reasonInfo struct {
	message   string
	hint      string
	retryable bool
}

// reasonTable maps deny reasons to static messages and agent-actionable hints.
// Internal error detail never crosses into these strings; it lives in audit.
var reasonTable = map[string]reasonInfo{
	ReasonUnauthenticated:     {"authentication failed", "authenticate with a supported scheme (see the service manifest)", true},
	ReasonInvalidDelegation:   {"delegation chain rejected", "re-issue the delegation credential or call without delegation", true},
	ReasonBoundaryViolation:   {"boundary access denied", "use a boundary you are a member of", false},
	ReasonOperationDenied:     {"operation denied", "request the capability grant required by this operation", false},
	ReasonResourceDenied:      {"resource access denied", "request access to this resource, or omit the resource", false},
	ReasonFieldDenied:         {"field access denied", "request fewer fields or obtain a field grant", false},
	ReasonPolicyDeny:          {"denied by policy", "ask an administrator for an explicit allow rule", false},
	ReasonPolicyError:         {"policy evaluation failed", "retry later; if persistent, contact an administrator", true},
	ReasonGuardrail:           {"rejected by safety guardrail", "fix the payload per the operation's input_schema and retry", false},
	ReasonRiskBlocked:         {"risk ceiling exceeded", "obtain approval or reduce request risk", false},
	ReasonApprovalRequired:    {"approval required", "obtain an approval token (approval.issue) and retry with approval_token", true},
	ReasonApprovalDenied:      {"approval rejected", "obtain a fresh approval token and retry", true},
	ReasonQuotaExceeded:       {"quota exceeded", "back off and retry later", true},
	ReasonIdempotencyConflict: {"idempotency key conflict", "retry with a new idempotency key, or the exact original payload", false},
	ReasonSchemaInvalid:       {"input failed schema validation", "validate input against the operation's input_schema (catalog.spec)", false},
	ReasonOperationUnknown:    {"unknown operation", "call catalog.spec to discover available operations and schemas", false},
	ReasonHandlerMissing:      {"operation unavailable", "contact an administrator; the operation is misconfigured", false},
	ReasonExecutionFailed:     {"execution failed", "safe to retry with the same idempotency key", true},
	ReasonOutputFilter:        {"output filtering failed", "contact an administrator; no data was returned", false},
	ReasonInternal:            {"internal error", "retry later; if persistent, contact an administrator", true},
	ReasonContextCanceled:     {"request canceled or deadline exceeded", "retry if the operation is still needed", true},
	ReasonExecutedUnconfirmed: {"execution may have completed but could not be confirmed", "query execution status using the execution_id before retrying", false},
}

// ReasonInfoFor returns the static caller-safe info for a deny reason.
// Unknown reasons fail closed to the internal-error entry.
func ReasonInfoFor(reason string) (message, hint string, retryable bool) {
	if ri, ok := reasonTable[reason]; ok {
		return ri.message, ri.hint, ri.retryable
	}
	ri := reasonTable[ReasonInternal]
	return ri.message, ri.hint, ri.retryable
}

// NewDenial constructs a Denial. Details may be nil.
// Retryable and Hint are populated from the static reason table;
// message is used as-is (callers must not pass internal error text —
// use SafeDenial when the detail came from an error).
func NewDenial(step, reason, message string, details map[string]string) *Denial {
	_, hint, retryable := ReasonInfoFor(reason)
	return &Denial{Step: step, Reason: reason, Message: message, Retryable: retryable, Hint: hint, Details: details}
}

// SafeDenial constructs a Denial whose message is the static per-reason text.
// Use it when the only available detail is an internal error string; that
// detail belongs in the audit record, not in the caller-facing denial.
func SafeDenial(step, reason string) *Denial {
	msg, hint, retryable := ReasonInfoFor(reason)
	return &Denial{Step: step, Reason: reason, Message: msg, Retryable: retryable, Hint: hint}
}

// IsDenial reports whether err is or wraps a *Denial.
func IsDenial(err error) bool {
	var d *Denial
	return errors.As(err, &d)
}

// AsDenial extracts *Denial if present.
func AsDenial(err error) (*Denial, bool) {
	var d *Denial
	if errors.As(err, &d) {
		return d, true
	}
	return nil, false
}

// Sentinel errors for non-policy failures (still fail-closed at runtime).
var (
	ErrNotFound        = errors.New("loom: not found")
	ErrAlreadyExists   = errors.New("loom: already exists")
	ErrInvalidArgument = errors.New("loom: invalid argument")
	ErrNotImplemented  = errors.New("loom: not implemented")
	ErrUnavailable     = errors.New("loom: unavailable")
)
