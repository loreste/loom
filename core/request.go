package core

import (
	"context"
	"time"
)

// PrincipalID is an opaque verified identity handle.
// Adapters must not mint these; only identity.Verifier does.
type PrincipalID string

// BoundaryID isolates tenants/environments/workspaces.
type BoundaryID string

// Boundary describes one isolation dimension. Tenant, project, environment,
// region, and security domain are represented as data rather than overloaded
// into one opaque string.
type Boundary struct {
	Type       string     `json:"type"`
	ID         BoundaryID `json:"id"`
	ParentType string     `json:"parent_type,omitempty"`
	ParentID   BoundaryID `json:"parent_id,omitempty"`
}

func (b Boundary) Valid() bool { return b.Type != "" && b.ID != "" }

// ResourceRef names a concrete resource subject to resource-level authz.
type ResourceRef struct {
	Type string // e.g. "document", "payment", "server"
	ID   string // opaque id within type
	// Attrs are non-authoritative metadata for policy context (never trusted alone).
	Attrs map[string]string
}

func (r ResourceRef) String() string {
	if r.Type == "" {
		return r.ID
	}
	if r.ID == "" {
		return r.Type
	}
	return r.Type + ":" + r.ID
}

// Credentials are untrusted input from the adapter (token, mTLS peer, API key…).
// The runtime never treats Credentials as proof of identity without verification.
type Credentials struct {
	// Scheme e.g. "bearer", "mtls", "api_key", "delegation".
	Scheme string
	// Token is the raw secret/material. Must not be logged.
	Token string
	// Claims are adapter-asserted metadata. Untrusted until verifier confirms.
	Claims map[string]string
}

// DelegationChain is an untrusted claim of acting-on-behalf-of.
// identity package validates each hop cryptographically / against store.
type DelegationChain struct {
	// Actor is the immediate caller principal claim (untrusted string).
	Actor string
	// OnBehalfOf is the principal the actor claims to represent.
	OnBehalfOf string
	// Scope limits delegated capabilities.
	Scope []string
	// Token is the delegation credential material.
	Token string
	// ExpiresAt if zero is treated as invalid by default verifier (fail-closed).
	ExpiresAt time.Time
}

// Request is the universal inbound unit after adapter translation.
// Everything here is untrusted until the pipeline verifies it.
type Request struct {
	// Operation name, e.g. "document.read".
	Operation string
	// OperationVersion binds this request to an exact registered contract.
	// Empty selects DefaultOperationVersion.
	OperationVersion string
	// ExecutionID is runtime-assigned and never accepted as caller authority.
	// Adapters must not populate it.
	ExecutionID string `json:"-"`

	// Credentials for authentication. Optional only if verifier accepts anonymous (default: no).
	Credentials Credentials

	// Delegation is optional. When set, must validate or deny.
	Delegation *DelegationChain

	// Boundary claimed by caller. Must match verified membership or deny.
	Boundary BoundaryID
	// BoundaryContext is the structured form of Boundary. When set, its ID
	// must match Boundary.
	BoundaryContext *Boundary

	// Resource primary subject, if any.
	Resource *ResourceRef

	// Input is operation payload (JSON-shaped map). Validated against schema.
	Input map[string]any

	// Fields requested for field-level authorization (output projection).
	// Empty means "all fields the policy allows", not "all fields that exist".
	Fields []string

	// IdempotencyKey for safe retries. Required when operation policy demands it.
	IdempotencyKey string

	// ApprovalToken proves prior approval when required.
	ApprovalToken string

	// TraceID correlates audit records. Generated if empty.
	TraceID string

	// Metadata is non-authoritative adapter baggage (user-agent, remote addr…).
	// Never used alone for allow decisions; may inform risk/guardrails.
	Metadata map[string]string

	// Deadline optional wall-clock bound; combined with context.
	Deadline time.Time
}

// Identity is the verified, runtime-trusted principal after authentication.
// Constructed only by identity.Verifier implementations.
type Identity struct {
	ID         PrincipalID
	Type       string // "user", "service", "agent", "system"
	Boundary   BoundaryID
	Attributes map[string]string
	// Capabilities are verified grants attached at auth time (optional cache).
	// Policy engine still re-evaluates; this is not a bypass.
	Capabilities []string
	// Delegator is set when acting via valid delegation.
	Delegator PrincipalID
	// AuthMethod records how identity was proven (for audit).
	AuthMethod string
}

// ExecutionContext is the fully authorized context handed to business logic.
// Handlers must not re-parse untrusted credentials; use only this.
type ExecutionContext struct {
	Ctx             context.Context
	Identity        Identity
	Boundary        BoundaryID
	BoundaryContext *Boundary
	Operation       *Operation
	Resource        *ResourceRef
	Input           map[string]any
	TraceID         string
	// Risk is the evaluated risk level after the risk engine ran.
	Risk RiskLevel
}

// Result is the handler outcome before output filtering.
type Result struct {
	// Output will be field-filtered and secret-redacted before return.
	Output map[string]any
	// EffectsActual may be recorded if handler reports additional effects.
	EffectsActual []Effect
}

// Response is what adapters may return to callers after full pipeline completion.
type Response struct {
	// Allowed is true only if execution completed successfully under policy.
	Allowed bool
	// Outcome is the caller-safe execution status. ExecutedUnconfirmed means
	// the handler may have produced a side effect but post-execution recording
	// failed; callers must check status before retrying.
	Outcome Outcome
	// ExecutionID identifies this execution attempt for reconciliation.
	ExecutionID string
	// OperationVersion is the exact registered contract selected for this
	// response. It is the normalized default for an unknown operation.
	OperationVersion string
	// Decision is allow/deny/require_approval.
	Decision Decision
	// Denial populated when not allowed.
	Denial *Denial
	// Output is filtered. Nil on deny.
	Output map[string]any
	// TraceID for correlation.
	TraceID string
	// AuditID of the emitted audit record.
	AuditID string
	// IdempotentReplay true when result was served from idempotency store.
	IdempotentReplay bool
	// Risk evaluated.
	Risk RiskLevel
	// ReliabilityWarning is set when execution succeeded but a durable
	// completion record still needs reconciliation.
	ReliabilityWarning string
}
