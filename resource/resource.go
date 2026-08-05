// Package resource evaluates resource-level authorization.
package resource

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/loreste/loom/core"
)

// Checker decides if an identity may act on a resource for an operation.
type Checker interface {
	Allow(ctx context.Context, id core.Identity, boundary core.BoundaryID, op *core.Operation, res *core.ResourceRef) error
}

// Rule is an explicit grant. Absence of a matching rule = deny.
type Rule struct {
	Principal core.PrincipalID // empty = any principal in boundary (still needs match)
	Boundary  core.BoundaryID
	// Type is resource type; empty matches any type only if ID pattern also empty (global) — discouraged.
	Type string
	// ID exact match; "*" means any id of Type (still requires Type).
	ID string
	// Operations allowed; empty means no operations (deny). "*" means any registered op name.
	Operations []string
}

// MemoryChecker is an explicit ACL. Default deny.
type MemoryChecker struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewMemoryChecker returns a deny-all resource checker.
func NewMemoryChecker() *MemoryChecker {
	return &MemoryChecker{}
}

// Grant appends a rule. Invalid rules rejected.
func (c *MemoryChecker) Grant(rule Rule) error {
	if c == nil {
		return fmt.Errorf("%w: nil checker", core.ErrInvalidArgument)
	}
	if rule.Boundary == "" {
		return fmt.Errorf("%w: boundary required", core.ErrInvalidArgument)
	}
	if len(rule.Operations) == 0 {
		return fmt.Errorf("%w: operations required (empty is not wildcard)", core.ErrInvalidArgument)
	}
	// Copy ops
	rule.Operations = append([]string(nil), rule.Operations...)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules = append(c.rules, rule)
	return nil
}

// Allow evaluates resource permission.
// Adversarial rules:
//   - nil resource: allowed only if operation declares no resource constraints
//   - resource present but op.Resources non-empty and type not listed → deny
//   - no matching rule → deny
//   - principal mismatch → skip rule
func (c *MemoryChecker) Allow(ctx context.Context, id core.Identity, boundary core.BoundaryID, op *core.Operation, res *core.ResourceRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("resource: checker not configured")
	}
	if op == nil {
		return fmt.Errorf("resource: nil operation")
	}

	if res == nil {
		if len(op.Resources) == 0 {
			return nil // op doesn't touch resources
		}
		return fmt.Errorf("resource: operation requires a resource")
	}

	// Type must be allowed by operation definition when Resources is set.
	if len(op.Resources) > 0 && !typeAllowed(op.Resources, res.Type) {
		return fmt.Errorf("resource: type %q not permitted for operation", res.Type)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, rule := range c.rules {
		if rule.Boundary != boundary {
			continue
		}
		if rule.Principal != "" && rule.Principal != id.ID {
			continue
		}
		if rule.Type != "" && rule.Type != res.Type {
			continue
		}
		if rule.ID != "" && rule.ID != "*" && rule.ID != res.ID {
			continue
		}
		if !opAllowed(rule.Operations, op.Name) {
			continue
		}
		return nil
	}
	return fmt.Errorf("resource: no grant for %s on %s", id.ID, res.String())
}

func typeAllowed(allowed []string, typ string) bool {
	for _, a := range allowed {
		if a == "*" || a == typ || strings.HasPrefix(typ, strings.TrimSuffix(a, "*")) && strings.HasSuffix(a, "*") {
			if a == "*" || a == typ {
				return true
			}
			prefix := strings.TrimSuffix(a, "*")
			if strings.HasPrefix(typ, prefix) {
				return true
			}
		}
	}
	return false
}

func opAllowed(ops []string, name string) bool {
	for _, o := range ops {
		if o == "*" || o == name {
			return true
		}
	}
	return false
}

// FieldFilter computes which output fields survive field-level authz.
// Default: if allowed set is empty after evaluation, deny all fields (empty map).
type FieldFilter struct {
	mu sync.RWMutex
	// principal|boundary|operation -> allowed fields; "*" field means all
	grants map[string]map[string]struct{}
}

// NewFieldFilter denies all fields until granted.
func NewFieldFilter() *FieldFilter {
	return &FieldFilter{grants: make(map[string]map[string]struct{})}
}

func fieldKey(id core.PrincipalID, b core.BoundaryID, op string) string {
	return string(id) + "|" + string(b) + "|" + op
}

// GrantFields allows fields for a principal/boundary/operation.
// Passing ["*"] allows all fields (still subject to secret redaction).
func (f *FieldFilter) GrantFields(id core.PrincipalID, b core.BoundaryID, op string, fields []string) error {
	if f == nil {
		return fmt.Errorf("%w: nil filter", core.ErrInvalidArgument)
	}
	if id == "" || b == "" || op == "" || len(fields) == 0 {
		return fmt.Errorf("%w: id, boundary, op, fields required", core.ErrInvalidArgument)
	}
	k := fieldKey(id, b, op)
	f.mu.Lock()
	defer f.mu.Unlock()
	set := f.grants[k]
	if set == nil {
		set = make(map[string]struct{})
		f.grants[k] = set
	}
	for _, field := range fields {
		set[field] = struct{}{}
	}
	return nil
}

// Filter returns a copy of output containing only allowed fields.
// Requested non-empty list further intersects.
//
// Sensitive fields (op.SensitiveFields):
//   - Never included by a bare "*" grant (adversarial default).
//   - Included only when the field name is explicitly granted.
//
// Unknown grants → empty object (not original output).
func (f *FieldFilter) Filter(id core.Identity, b core.BoundaryID, op string, requested []string, sensitive []string, output map[string]any) (map[string]any, error) {
	if output == nil {
		return map[string]any{}, nil
	}
	if f == nil {
		// Fail closed: no filter configured → strip everything.
		return map[string]any{}, fmt.Errorf("resource: field filter not configured")
	}
	// Hold RLock for the whole evaluation: GrantFields mutates the inner
	// grant set under the write lock, so reading it after RUnlock races.
	f.mu.RLock()
	defer f.mu.RUnlock()
	grant := f.grants[fieldKey(id.ID, b, op)]

	sens := make(map[string]struct{}, len(sensitive))
	for _, s := range sensitive {
		sens[s] = struct{}{}
	}

	allowAll := false
	if grant != nil {
		if _, ok := grant["*"]; ok {
			allowAll = true
		}
	}

	reqSet := map[string]struct{}{}
	for _, r := range requested {
		reqSet[r] = struct{}{}
	}
	restrictReq := len(requested) > 0

	out := make(map[string]any)
	for k, v := range output {
		if restrictReq {
			if _, ok := reqSet[k]; !ok {
				continue
			}
		}
		_, isSensitive := sens[k]
		if isSensitive {
			// Explicit field grant required; "*" is not enough.
			if grant == nil {
				continue
			}
			if _, ok := grant[k]; !ok {
				continue
			}
		} else if !allowAll {
			if grant == nil {
				continue
			}
			if _, ok := grant[k]; !ok {
				continue
			}
		}
		out[k] = v
	}
	return out, nil
}
