// Package approval gates high-risk operations. No token ⇒ no execution when required.
package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Decision from the approval engine.
type Decision struct {
	// Required means execution must not proceed without a valid token.
	Required bool
	// Approved means a valid token was presented (or approval not required).
	Approved bool
	// Message for audit.
	Message string
}

// Engine decides if approval is needed and whether the request satisfies it.
//
// Evaluate only CHECKS the token — it must never consume it.
// Consume burns a single-use token. The runtime claims (Consume) BEFORE the
// handler so concurrent requests cannot double-execute money/write ops.
// Trade-off: a handler failure after Consume still burns the token (fail closed).
type Engine interface {
	// Evaluate checks requirement and token validity without consuming.
	// The stored record boundary must match the request boundary exactly
	// (fail closed: a token issued for "dev" is invalid in "prod"; a stored
	// empty boundary only matches an empty request boundary).
	Evaluate(ctx context.Context, id core.Identity, op *core.Operation, risk core.RiskLevel, boundary core.BoundaryID, token string) Decision
	// Consume burns a single-use token (atomic claim).
	// It re-checks principal/operation/boundary/expiry atomically.
	// An error means the token was NOT consumed (fail closed).
	// Concurrent Consume of the same token: exactly one succeeds.
	Consume(ctx context.Context, id core.Identity, op *core.Operation, boundary core.BoundaryID, token string) error
}

// VersionedIssuer issues an approval bound to an exact operation version.
// Issuer remains available for compatibility and binds tokens to version 1.
type VersionedIssuer interface {
	IssueVersioned(token string, principal core.PrincipalID, op string, version string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error
}

// Record is a stored pre-approval.
type Record struct {
	TokenHash        string
	Principal        core.PrincipalID
	Operation        string
	OperationVersion string
	Boundary         core.BoundaryID
	ExpiresAt        time.Time
	MaxRisk          core.RiskLevel
	Consumed         bool
	SingleUse        bool
}

// MemoryEngine stores issued approval tokens.
// Adversarial defaults:
//   - Tokens are hashed at rest
//   - Single-use by default when issued via Issue
//   - Expired / wrong principal / wrong op → not approved
//   - Missing token when required → not approved (never implicit)
type MemoryEngine struct {
	mu     sync.Mutex
	tokens map[string]*Record
}

// Durable reports whether approval state survives process restart. Memory
// state is intentionally false so production constructors can reject it.
func (e *MemoryEngine) Durable() bool { return false }

// NewMemoryEngine creates an empty approval store.
func NewMemoryEngine() *MemoryEngine {
	return &MemoryEngine{tokens: make(map[string]*Record)}
}

func hashTok(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue registers an approval token. Returns error on bad input.
func (e *MemoryEngine) Issue(token string, principal core.PrincipalID, op string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	return e.IssueVersioned(token, principal, op, core.DefaultOperationVersion, boundary, maxRisk, ttl)
}

// IssueVersioned binds an approval token to one exact operation version.
func (e *MemoryEngine) IssueVersioned(token string, principal core.PrincipalID, op string, version string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	if e == nil {
		return fmt.Errorf("%w: nil engine", core.ErrInvalidArgument)
	}
	if token == "" || principal == "" || op == "" {
		return fmt.Errorf("%w: token, principal, operation required", core.ErrInvalidArgument)
	}
	if ttl <= 0 {
		return fmt.Errorf("%w: ttl must be positive", core.ErrInvalidArgument)
	}
	h := hashTok(token)
	e.mu.Lock()
	defer e.mu.Unlock()
	// Never resurrect a burned or existing token string (fail closed).
	if prev, ok := e.tokens[h]; ok {
		if prev.Consumed {
			return fmt.Errorf("%w: approval token already used; issue a new token", core.ErrAlreadyExists)
		}
		return fmt.Errorf("%w: approval token already issued", core.ErrAlreadyExists)
	}
	e.tokens[h] = &Record{
		TokenHash:        h,
		Principal:        principal,
		Operation:        op,
		OperationVersion: core.NormalizeOperationVersion(version),
		Boundary:         boundary,
		ExpiresAt:        time.Now().Add(ttl),
		MaxRisk:          maxRisk,
		SingleUse:        true,
	}
	return nil
}

// checkRecord validates a stored record against the caller. Returns "" if valid,
// else a static rejection message. Boundary must match exactly (fail closed).
func checkRecord(rec *Record, id core.Identity, op *core.Operation, boundary core.BoundaryID, risk core.RiskLevel) string {
	if rec.Consumed {
		return "approval token already consumed"
	}
	if time.Now().After(rec.ExpiresAt) {
		return "approval token expired"
	}
	if rec.Principal != id.ID {
		return "approval principal mismatch"
	}
	if core.NormalizeOperationVersion(rec.OperationVersion) != core.NormalizeOperationVersion(op.Version) {
		return "approval operation version mismatch"
	}
	if rec.Operation != "*" && rec.Operation != op.Name {
		return "approval operation mismatch"
	}
	if rec.Boundary != boundary {
		return "approval boundary mismatch"
	}
	if risk > rec.MaxRisk {
		return "risk exceeds approved maximum"
	}
	return ""
}

// Evaluate implements Engine. It checks the token but never consumes it;
// the runtime calls Consume only after the handler succeeded.
func (e *MemoryEngine) Evaluate(_ context.Context, id core.Identity, op *core.Operation, risk core.RiskLevel, boundary core.BoundaryID, token string) Decision {
	if op == nil {
		return Decision{Required: true, Approved: false, Message: "nil operation"}
	}
	required := approvalRequired(op, risk)
	if !required {
		return Decision{Required: false, Approved: true, Message: "approval not required"}
	}
	if token == "" {
		return Decision{Required: true, Approved: false, Message: "approval token required"}
	}
	if e == nil {
		return Decision{Required: true, Approved: false, Message: "approval engine not configured"}
	}
	h := hashTok(token)
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.tokens[h]
	if !ok {
		return Decision{Required: true, Approved: false, Message: "unknown approval token"}
	}
	if msg := checkRecord(rec, id, op, boundary, risk); msg != "" {
		return Decision{Required: true, Approved: false, Message: msg}
	}
	return Decision{Required: true, Approved: true, Message: "approval token accepted"}
}

// Consume implements Engine. Burns the single-use token after successful execution.
func (e *MemoryEngine) Consume(_ context.Context, id core.Identity, op *core.Operation, boundary core.BoundaryID, token string) error {
	if e == nil {
		return fmt.Errorf("%w: nil engine", core.ErrInvalidArgument)
	}
	if token == "" || op == nil {
		return fmt.Errorf("%w: token and operation required", core.ErrInvalidArgument)
	}
	h := hashTok(token)
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.tokens[h]
	if !ok {
		return fmt.Errorf("approval: unknown token")
	}
	if msg := checkRecord(rec, id, op, boundary, rec.MaxRisk); msg != "" {
		return fmt.Errorf("approval: %s", msg)
	}
	if rec.SingleUse {
		rec.Consumed = true
	}
	return nil
}

// Required reports whether approval is needed for op at the given risk level.
func Required(op *core.Operation, risk core.RiskLevel) bool {
	if op == nil {
		return true
	}
	if op.Approval.Required {
		return true
	}
	// MinRisk: trigger when risk >= MinRisk and MinRisk is above Low.
	if risk >= op.Approval.MinRisk && op.Approval.MinRisk > core.RiskLow {
		return true
	}
	for _, e := range op.Approval.Effects {
		if op.HasEffect(e) {
			return true
		}
	}
	// Critical always requires approval.
	if risk >= core.RiskCritical {
		return true
	}
	return false
}

func approvalRequired(op *core.Operation, risk core.RiskLevel) bool {
	return Required(op, risk)
}
