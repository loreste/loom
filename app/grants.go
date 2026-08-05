package app

import (
	"context"
	"fmt"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/resource"
)

// DBAccess describes least-privilege DB grants for a principal.
type DBAccess struct {
	Principal core.PrincipalID
	Boundary  core.BoundaryID
	// Pool resource id (db resource type). Use "*" only if you accept broad access.
	Pool string
	// Query allows db.query
	Query bool
	// Exec allows db.exec (writes; still subject to approval policy on the op)
	Exec bool
}

// GrantDBAccess installs policy + resource + field grants for database ops.
// Caps must already exist on the principal (AddUser capabilities).
func (a *App) GrantDBAccess(g DBAccess) error {
	if a == nil {
		return fmt.Errorf("%w: nil app", core.ErrInvalidArgument)
	}
	if g.Principal == "" || g.Boundary == "" || g.Pool == "" {
		return fmt.Errorf("%w: principal, boundary, pool required", core.ErrInvalidArgument)
	}
	if !g.Query && !g.Exec {
		return fmt.Errorf("%w: enable Query and/or Exec", core.ErrInvalidArgument)
	}
	var ops []string
	if g.Query {
		ops = append(ops, "db.query")
		if err := a.AllowPolicy(policy.Rule{
			Principal: g.Principal, Boundary: g.Boundary, Operation: "db.query", Priority: 10,
		}); err != nil {
			return err
		}
		if err := a.AllowFields(g.Principal, g.Boundary, "db.query",
			[]string{"pool", "columns", "rows", "count", "truncated"}); err != nil {
			return err
		}
		if err := a.AllowInputFields(g.Principal, g.Boundary, "db.query", []string{"pool", "sql", "args"}); err != nil {
			return err
		}
	}
	if g.Exec {
		ops = append(ops, "db.exec")
		if err := a.AllowPolicy(policy.Rule{
			Principal: g.Principal, Boundary: g.Boundary, Operation: "db.exec", Priority: 10,
		}); err != nil {
			return err
		}
		if err := a.AllowFields(g.Principal, g.Boundary, "db.exec",
			[]string{"pool", "rows_affected", "status"}); err != nil {
			return err
		}
		if err := a.AllowInputFields(g.Principal, g.Boundary, "db.exec", []string{"pool", "sql", "args"}); err != nil {
			return err
		}
	}
	return a.AllowResource(resource.Rule{
		Principal:  g.Principal,
		Boundary:   g.Boundary,
		Type:       "db",
		ID:         g.Pool,
		Operations: ops,
	})
}

// GrantOp is a one-shot allow for a custom operation (policy + optional resource + fields).
func (a *App) GrantOp(principal core.PrincipalID, boundary core.BoundaryID, op string, resType, resID string, fields []string) error {
	if err := a.AllowPolicy(policy.Rule{
		Principal: principal, Boundary: boundary, Operation: op, Priority: 10,
	}); err != nil {
		return err
	}
	if resType != "" {
		if resID == "" {
			resID = "*"
		}
		if err := a.AllowResource(resource.Rule{
			Principal: principal, Boundary: boundary, Type: resType, ID: resID,
			Operations: []string{op},
		}); err != nil {
			return err
		}
	}
	if len(fields) > 0 {
		return a.AllowFields(principal, boundary, op, fields)
	}
	return nil
}

// CallAs is a convenience for embed call sites.
func (a *App) CallAs(ctx context.Context, token, operation string, boundary core.BoundaryID, input map[string]any) core.Response {
	return a.Call(ctx, core.Request{
		Operation:   operation,
		Credentials: core.Credentials{Scheme: "bearer", Token: token},
		Boundary:    boundary,
		Input:       input,
	})
}
