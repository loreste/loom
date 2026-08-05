// Package tenancy resolves a verified tenant claim into Loom's boundary
// context. It does not trust request metadata or caller-supplied tenant IDs.
package tenancy

import (
	"context"
	"fmt"
	"strings"

	"github.com/loreste/loom/core"
)

// Resolver binds a verified identity attribute to the requested boundary.
// The request boundary is still required so adapters cannot silently choose a
// tenant by omission.
type Resolver struct {
	// Attribute is the verified Identity.Attributes key, such as tenant_id.
	Attribute string
	// Required rejects identities without the configured attribute.
	Required bool
}

// NewResolver constructs a tenant resolver for an identity attribute.
func NewResolver(attribute string) (*Resolver, error) {
	attribute = strings.TrimSpace(attribute)
	if attribute == "" {
		return nil, fmt.Errorf("tenancy: identity attribute required")
	}
	return &Resolver{Attribute: attribute, Required: true}, nil
}

// Resolve returns the only boundary the identity is allowed to use.
// Missing, conflicting, or empty tenant context fails closed.
func (r *Resolver) Resolve(ctx context.Context, id core.Identity, requested core.BoundaryID) (core.BoundaryID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	requested = core.BoundaryID(strings.TrimSpace(string(requested)))
	if requested == "" {
		return "", fmt.Errorf("tenancy: requested boundary is required")
	}
	if r == nil || strings.TrimSpace(r.Attribute) == "" {
		return "", fmt.Errorf("tenancy: resolver not configured")
	}
	if id.Boundary != "" && id.Boundary != requested {
		return "", fmt.Errorf("tenancy: identity home boundary does not match request")
	}
	claim := strings.TrimSpace(id.Attributes[r.Attribute])
	if claim == "" {
		if r.Required {
			return "", fmt.Errorf("tenancy: verified tenant claim %q is missing", r.Attribute)
		}
		return requested, nil
	}
	if claim != string(requested) {
		return "", fmt.Errorf("tenancy: verified tenant claim does not match requested boundary")
	}
	return requested, nil
}
