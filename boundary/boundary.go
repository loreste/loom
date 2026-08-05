// Package boundary enforces tenant/environment isolation.
// A verified identity still cannot act outside its allowed boundaries.
package boundary

import (
	"context"
	"fmt"
	"sync"

	"github.com/loreste/loom/core"
)

// Checker validates that an identity may operate inside a boundary.
type Checker interface {
	// Allow returns nil if id may act in boundary. Any error = deny.
	Allow(ctx context.Context, id core.Identity, boundary core.BoundaryID) error
}

// MemoryChecker maps principal → set of allowed boundaries.
// Default deny: missing membership is rejection.
// Empty requested boundary is deny unless policy explicitly allows a default
// (this checker never invents a default boundary).
type MemoryChecker struct {
	mu   sync.RWMutex
	// principal -> boundary -> struct{}
	member map[core.PrincipalID]map[core.BoundaryID]struct{}
}

// NewMemoryChecker creates an empty membership store.
func NewMemoryChecker() *MemoryChecker {
	return &MemoryChecker{member: make(map[core.PrincipalID]map[core.BoundaryID]struct{})}
}

// Grant adds membership. Empty ids rejected.
func (c *MemoryChecker) Grant(principal core.PrincipalID, boundary core.BoundaryID) error {
	if c == nil {
		return fmt.Errorf("%w: nil checker", core.ErrInvalidArgument)
	}
	if principal == "" || boundary == "" {
		return fmt.Errorf("%w: principal and boundary required", core.ErrInvalidArgument)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.member[principal] == nil {
		c.member[principal] = make(map[core.BoundaryID]struct{})
	}
	c.member[principal][boundary] = struct{}{}
	return nil
}

// Revoke removes membership (idempotent).
func (c *MemoryChecker) Revoke(principal core.PrincipalID, boundary core.BoundaryID) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.member[principal]; m != nil {
		delete(m, boundary)
	}
}

// Allow enforces membership. Adversarial rules:
//   - empty boundary → deny
//   - identity.Boundary set and differs from requested → deny (no cross-boundary spoof)
//   - not in membership map → deny
func (c *MemoryChecker) Allow(ctx context.Context, id core.Identity, boundary core.BoundaryID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("boundary: checker not configured")
	}
	if boundary == "" {
		return fmt.Errorf("boundary: empty boundary")
	}
	// If identity is pinned to a home boundary, request must match.
	if id.Boundary != "" && id.Boundary != boundary {
		return fmt.Errorf("boundary: identity home %q != requested %q", id.Boundary, boundary)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.member[id.ID]
	if !ok {
		return fmt.Errorf("boundary: principal not a member of any boundary")
	}
	if _, ok := m[boundary]; !ok {
		return fmt.Errorf("boundary: principal not a member of %q", boundary)
	}
	return nil
}
