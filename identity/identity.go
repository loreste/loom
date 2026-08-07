// Package identity authenticates callers. Claims from adapters are untrusted.
// Only Verifier implementations mint core.Identity.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Verifier authenticates credentials into a trusted Identity.
// Implementations must fail closed: any uncertainty → error (runtime maps to deny).
type Verifier interface {
	Authenticate(ctx context.Context, creds core.Credentials) (core.Identity, error)
}

// DelegationValidator validates acting-on-behalf-of chains.
type DelegationValidator interface {
	Validate(ctx context.Context, actor core.Identity, del *core.DelegationChain) (core.Identity, error)
}

// StaticPrincipal is an explicitly provisioned principal (dev/test and simple deploys).
// Production should swap for JWT/mTLS/OIDC verifiers without changing the pipeline.
type StaticPrincipal struct {
	ID           core.PrincipalID
	Type         string
	Boundary     core.BoundaryID
	Token        string // raw shared secret; compared in constant time via hash
	tokenHash    string
	Attributes   map[string]string
	Capabilities []string
}

// MemoryVerifier is an in-memory credential store. Default: deny unknown tokens.
// Adversarial notes:
//   - Empty token never authenticates.
//   - Unknown token never authenticates.
//   - Token comparison uses hashed equality; raw tokens are not stored after Register.
type MemoryVerifier struct {
	mu     sync.RWMutex
	byHash map[string]StaticPrincipal
}

// NewMemoryVerifier creates an empty verifier (everyone denied until registered).
func NewMemoryVerifier() *MemoryVerifier {
	return &MemoryVerifier{byHash: make(map[string]StaticPrincipal)}
}

func hashToken(scheme, token string) string {
	sum := sha256.Sum256([]byte(scheme + "\x00" + token))
	return hex.EncodeToString(sum[:])
}

// Register adds a principal. Empty token is rejected.
func (v *MemoryVerifier) Register(p StaticPrincipal) error {
	if v == nil {
		return fmt.Errorf("%w: nil verifier", core.ErrInvalidArgument)
	}
	if p.ID == "" || p.Token == "" {
		return fmt.Errorf("%w: id and token required", core.ErrInvalidArgument)
	}
	if p.Type == "" {
		p.Type = "user"
	}
	p.tokenHash = hashToken("bearer", p.Token)
	p.Token = "" // do not retain raw secret
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.byHash[p.tokenHash]; exists {
		return fmt.Errorf("%w: token already registered", core.ErrAlreadyExists)
	}
	v.byHash[p.tokenHash] = p
	return nil
}

// Authenticate verifies credentials. Fail-closed on empty/unknown.
func (v *MemoryVerifier) Authenticate(ctx context.Context, creds core.Credentials) (core.Identity, error) {
	if err := ctx.Err(); err != nil {
		return core.Identity{}, err
	}
	if v == nil {
		return core.Identity{}, fmt.Errorf("identity: verifier not configured")
	}
	scheme := creds.Scheme
	if scheme == "" {
		scheme = "bearer"
	}
	if creds.Token == "" {
		return core.Identity{}, fmt.Errorf("identity: empty credentials")
	}
	h := hashToken(scheme, creds.Token)
	v.mu.RLock()
	p, ok := v.byHash[h]
	v.mu.RUnlock()
	if !ok {
		// Do not reveal whether token format was wrong vs unknown.
		return core.Identity{}, fmt.Errorf("identity: authentication failed")
	}
	attrs := map[string]string{}
	for k, val := range p.Attributes {
		attrs[k] = val
	}
	caps := append([]string(nil), p.Capabilities...)
	return core.Identity{
		ID:           p.ID,
		Type:         p.Type,
		Boundary:     p.Boundary,
		Attributes:   attrs,
		Capabilities: caps,
		AuthMethod:   scheme,
	}, nil
}

// MemoryDelegation validates simple scoped delegation tokens held in memory.
// Rules (adversarial):
//   - nil chain → invalid if caller expected delegation (caller decides)
//   - expired or zero ExpiresAt → invalid
//   - actor mismatch → invalid
//   - empty OnBehalfOf → invalid
//   - scope empty means no capabilities (not "all")
type MemoryDelegation struct {
	mu sync.RWMutex
	// tokenHash -> record
	tokens map[string]delegationRecord
}

type delegationRecord struct {
	Actor      core.PrincipalID
	OnBehalfOf core.PrincipalID
	Scope      []string
	Boundary   core.BoundaryID
	ExpiresAt  time.Time
}

// NewMemoryDelegation returns an empty store (all delegations invalid).
func NewMemoryDelegation() *MemoryDelegation {
	return &MemoryDelegation{tokens: make(map[string]delegationRecord)}
}

// Issue registers a delegation token. Zero ExpiresAt rejected.
func (d *MemoryDelegation) Issue(token string, actor, onBehalfOf core.PrincipalID, scope []string, boundary core.BoundaryID, exp time.Time) error {
	if d == nil {
		return fmt.Errorf("%w: nil store", core.ErrInvalidArgument)
	}
	if token == "" || actor == "" || onBehalfOf == "" {
		return fmt.Errorf("%w: token, actor, onBehalfOf required", core.ErrInvalidArgument)
	}
	if exp.IsZero() || time.Now().After(exp) {
		return fmt.Errorf("%w: expiry must be in the future", core.ErrInvalidArgument)
	}
	h := hashToken("delegation", token)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokens[h] = delegationRecord{
		Actor:      actor,
		OnBehalfOf: onBehalfOf,
		Scope:      append([]string(nil), scope...),
		Boundary:   boundary,
		ExpiresAt:  exp,
	}
	return nil
}

// Validate checks the chain against the authenticated actor.
func (d *MemoryDelegation) Validate(ctx context.Context, actor core.Identity, del *core.DelegationChain) (core.Identity, error) {
	if err := ctx.Err(); err != nil {
		return core.Identity{}, err
	}
	if d == nil || del == nil {
		return core.Identity{}, fmt.Errorf("identity: invalid delegation")
	}
	if del.Token == "" {
		return core.Identity{}, fmt.Errorf("identity: missing delegation token")
	}
	h := hashToken("delegation", del.Token)
	d.mu.RLock()
	rec, ok := d.tokens[h]
	d.mu.RUnlock()
	if !ok {
		return core.Identity{}, fmt.Errorf("identity: delegation not found")
	}
	if time.Now().After(rec.ExpiresAt) {
		return core.Identity{}, fmt.Errorf("identity: delegation expired")
	}
	if rec.Actor != actor.ID {
		return core.Identity{}, fmt.Errorf("identity: delegation actor mismatch")
	}
	// Claimed OnBehalfOf must match issued record (caller cannot escalate target).
	if del.OnBehalfOf != "" && core.PrincipalID(del.OnBehalfOf) != rec.OnBehalfOf {
		return core.Identity{}, fmt.Errorf("identity: on_behalf_of mismatch")
	}
	// Intersect claimed scope with issued scope; empty issued scope = no caps.
	scope := intersectScope(rec.Scope, del.Scope)
	boundary := rec.Boundary
	if boundary == "" {
		boundary = actor.Boundary
	}
	return core.Identity{
		ID:           rec.OnBehalfOf,
		Type:         "delegated",
		Boundary:     boundary,
		Attributes:   map[string]string{"delegated_by": string(actor.ID)},
		Capabilities: scope,
		Delegator:    actor.ID,
		AuthMethod:   "delegation",
	}, nil
}

// intersectScope: if claimed is empty, use issued; else intersection.
// Empty intersection = no capabilities (deny by capability checks later).
func intersectScope(issued, claimed []string) []string {
	if len(issued) == 0 {
		return nil
	}
	if len(claimed) == 0 {
		return append([]string(nil), issued...)
	}
	set := make(map[string]struct{}, len(issued))
	for _, s := range issued {
		set[normalizeCap(s)] = struct{}{}
	}
	var out []string
	for _, c := range claimed {
		c = normalizeCap(c)
		if _, ok := set[c]; ok {
			out = append(out, c)
		}
	}
	return out
}

func normalizeCap(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
