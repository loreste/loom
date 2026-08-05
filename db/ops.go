package db

import (
	"fmt"

	"github.com/loreste/loom/core"
)

const (
	OpQuery = "db.query"
	OpExec  = "db.exec"
)

// RegisterOps adds governed database operations to the registry.
// All SQL still goes through Classify + pool options; Loom policy still applies.
func RegisterOps(reg *core.Registry, dbs *Registry) error {
	if reg == nil || dbs == nil {
		return fmt.Errorf("%w: registry and db registry required", core.ErrInvalidArgument)
	}
	querySchema := []byte(`{
		"type":"object",
		"properties":{
			"pool":{"type":"string","minLength":1,"maxLength":64},
			"sql":{"type":"string","minLength":1,"maxLength":16384},
			"args":{"type":"array","maxItems":64}
		},
		"required":["pool","sql"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:            OpQuery,
		Description:     "Run a parameterized read query on a registered pool",
		InputSchema:     querySchema,
		Permissions:     []string{"db.query"},
		Resources:       []string{"db"},
		Risk:            core.RiskMedium,
		Effects:         []core.Effect{core.EffectRead},
		SensitiveFields: []string{"sql"},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleQuery(ec, dbs)
	}); err != nil {
		return err
	}

	execSchema := querySchema
	return reg.Register(&core.Operation{
		Name:            OpExec,
		Description:     "Run a parameterized write statement on a registered pool",
		InputSchema:     execSchema,
		Permissions:     []string{"db.exec"},
		Resources:       []string{"db"},
		Risk:            core.RiskHigh,
		Effects:         []core.Effect{core.EffectWrite},
		Approval:        core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Idempotency:     core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
		Quota:           core.QuotaPolicy{Enabled: true},
		SensitiveFields: []string{"sql"},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleExec(ec, dbs)
	})
}

func handleQuery(ec *core.ExecutionContext, dbs *Registry) (*core.Result, error) {
	pool, sqlText, args, err := parseSQLInput(ec)
	if err != nil {
		return nil, err
	}
	// Resource should match pool name when provided
	if ec.Resource != nil {
		if ec.Resource.Type != "db" {
			return nil, fmt.Errorf("resource type must be db")
		}
		if ec.Resource.ID != "" && ec.Resource.ID != pool {
			return nil, fmt.Errorf("resource id must match pool")
		}
	}
	ex, err := dbs.ExecutorFor(pool, ec.Identity, ec.Boundary)
	if err != nil {
		return nil, err
	}
	rs, err := ex.Query(ec.Ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	return &core.Result{Output: map[string]any{
		"pool":      pool,
		"columns":   rs.Columns,
		"rows":      rs.Rows,
		"count":     len(rs.Rows),
		"truncated": rs.Truncated,
	}}, nil
}

func handleExec(ec *core.ExecutionContext, dbs *Registry) (*core.Result, error) {
	pool, sqlText, args, err := parseSQLInput(ec)
	if err != nil {
		return nil, err
	}
	if ec.Resource != nil {
		if ec.Resource.Type != "db" {
			return nil, fmt.Errorf("resource type must be db")
		}
		if ec.Resource.ID != "" && ec.Resource.ID != pool {
			return nil, fmt.Errorf("resource id must match pool")
		}
	}
	ex, err := dbs.ExecutorFor(pool, ec.Identity, ec.Boundary)
	if err != nil {
		return nil, err
	}
	res, err := ex.Exec(ec.Ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	return &core.Result{Output: map[string]any{
		"pool":          pool,
		"rows_affected": res.RowsAffected,
		"status":        "ok",
	}}, nil
}

func parseSQLInput(ec *core.ExecutionContext) (pool, sqlText string, args []any, err error) {
	pool, _ = ec.Input["pool"].(string)
	sqlText, _ = ec.Input["sql"].(string)
	if pool == "" || sqlText == "" {
		return "", "", nil, fmt.Errorf("pool and sql required")
	}
	if raw, ok := ec.Input["args"].([]any); ok {
		args = raw
	}
	return pool, sqlText, args, nil
}
