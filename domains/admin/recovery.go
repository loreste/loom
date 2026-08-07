package admin

import (
	"fmt"
	"strings"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
)

const (
	OpRecoveryList       = "recovery.list"
	OpRecoveryRequeue    = "recovery.requeue"
	OpRecoveryDeadLetter = "recovery.dead_letter"
)

// RecoveryDeps provides the durable store to governed recovery-admin ops.
// The handlers expose only bounded status summaries and never business input.
type RecoveryDeps struct {
	Store execution.RecoveryAdmin
}

// RegisterRecovery registers operator recovery controls. Mutation operations
// require an approval token and must still be granted by policy explicitly.
func RegisterRecovery(reg *core.Registry, deps RecoveryDeps) error {
	if reg == nil || deps.Store == nil {
		return fmt.Errorf("%w: recovery admin store required", core.ErrInvalidArgument)
	}
	listSchema := []byte(`{"type":"object","properties":{"state":{"type":"string","enum":["executed_unconfirmed","operator_review"]},"limit":{"type":"integer","minimum":1,"maximum":1000}},"additionalProperties":false}`)
	if err := reg.Register(&core.Operation{
		Name:        OpRecoveryList,
		Description: "List bounded recovery and operator-review status summaries",
		InputSchema: listSchema,
		Permissions: []string{"recovery.read"},
		Risk:        core.RiskMedium,
		Effects:     []core.Effect{core.EffectRead, core.EffectAdmin},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleRecoveryList(ec, deps)
	}); err != nil {
		return err
	}
	mutationSchema := []byte(`{"type":"object","properties":{"execution_id":{"type":"string","minLength":1,"maxLength":128},"reason":{"type":"string","maxLength":512}},"required":["execution_id"],"additionalProperties":false}`)
	if err := reg.Register(&core.Operation{
		Name:        OpRecoveryRequeue,
		Description: "Requeue an operator-review execution for safe reconciliation",
		InputSchema: mutationSchema,
		Permissions: []string{"recovery.requeue"},
		Risk:        core.RiskHigh,
		Effects:     []core.Effect{core.EffectAdmin, core.EffectWrite},
		Approval:    core.ApprovalPolicy{Required: true},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleRecoveryMutation(ec, deps, false)
	}); err != nil {
		return err
	}
	return reg.Register(&core.Operation{
		Name:        OpRecoveryDeadLetter,
		Description: "Move a recoverable execution to operator review",
		InputSchema: mutationSchema,
		Permissions: []string{"recovery.dead_letter"},
		Risk:        core.RiskCritical,
		Effects:     []core.Effect{core.EffectAdmin, core.EffectWrite},
		Approval:    core.ApprovalPolicy{Required: true},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handleRecoveryMutation(ec, deps, true)
	})
}

func handleRecoveryList(ec *core.ExecutionContext, deps RecoveryDeps) (*core.Result, error) {
	state, _ := ec.Input["state"].(string)
	limit := 100
	if raw, ok := ec.Input["limit"].(float64); ok && raw > 0 {
		limit = int(raw)
	}
	records, err := deps.Store.ListRecovery(ec.Ctx, execution.State(strings.TrimSpace(state)), limit)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(records))
	for _, record := range records {
		items = append(items, recoverySummary(record))
	}
	return &core.Result{Output: map[string]any{"records": items, "count": len(items)}}, nil
}

func handleRecoveryMutation(ec *core.ExecutionContext, deps RecoveryDeps, deadLetter bool) (*core.Result, error) {
	id, _ := ec.Input["execution_id"].(string)
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("execution_id is required")
	}
	reason, _ := ec.Input["reason"].(string)
	var record execution.Record
	var err error
	if deadLetter {
		record, err = deps.Store.DeadLetterRecoveryAdmin(ec.Ctx, id, reason)
	} else {
		record, err = deps.Store.RequeueRecovery(ec.Ctx, id, reason)
	}
	if err != nil {
		return nil, err
	}
	return &core.Result{Output: recoverySummary(record)}, nil
}

func recoverySummary(record execution.Record) map[string]any {
	output := map[string]any{
		"execution_id":          record.ExecutionID,
		"operation":             record.Operation,
		"operation_version":     record.OperationVersion,
		"boundary":              record.Boundary,
		"state":                 record.State,
		"outcome":               record.Outcome.String(),
		"recovery_attempt":      record.RecoveryAttempt,
		"recovery_escalated":    record.RecoveryEscalated,
		"last_failure_category": record.LastFailureCategory,
		"last_failure_summary":  record.LastFailureSummary,
		"updated_at":            record.UpdatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
	if !record.NextAttemptAt.IsZero() {
		output["next_attempt_at"] = record.NextAttemptAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	return output
}
