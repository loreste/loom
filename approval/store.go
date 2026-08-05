package approval

import (
	"context"
	"time"

	"github.com/loreste/loom/core"
)

// Issuer creates approval tokens. Must only be reachable via governed operations
// or trusted bootstrap — never an unauthenticated HTTP shortcut.
type Issuer interface {
	Issue(token string, principal core.PrincipalID, op string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error
}

// Store is Evaluate + Issue (persistent or memory).
type Store interface {
	Engine
	Issuer
}

// Ensure MemoryEngine implements Store.
var _ Store = (*MemoryEngine)(nil)

// IssueContext is optional metadata for future audit of issuance (not privileges).
type IssueContext struct {
	IssuedBy core.PrincipalID
	TraceID  string
}

// Evaluate is re-exported path for interface embedding tests.
func Evaluate(ctx context.Context, e Engine, id core.Identity, op *core.Operation, risk core.RiskLevel, boundary core.BoundaryID, token string) Decision {
	if e == nil {
		return Decision{Required: true, Approved: false, Message: "approval engine not configured"}
	}
	return e.Evaluate(ctx, id, op, risk, boundary, token)
}
