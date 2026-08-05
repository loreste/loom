// Package execution stores caller-safe execution records for reconciliation.
// Records never contain raw credentials or unrestricted request input.
package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/loreste/loom/core"
)

// State describes the lifecycle of an execution attempt.
type State string

const (
	StatePending             State = "pending"
	StateAllowed             State = "allowed"
	StateDenied              State = "denied"
	StateExecutedUnconfirmed State = "executed_unconfirmed"
	StateReconciled          State = "reconciled"
)

// Record is the durable, caller-safe status of one execution attempt.
// Response contains only filtered output and safe denial text. Input is never
// stored here.
type Record struct {
	ExecutionID        string        `json:"execution_id"`
	Operation          string        `json:"operation"`
	OperationVersion   string        `json:"operation_version"`
	Principal          string        `json:"principal,omitempty"`
	Boundary           string        `json:"boundary,omitempty"`
	Outcome            core.Outcome  `json:"outcome"`
	State              State         `json:"state"`
	Response           core.Response `json:"response"`
	IdempotencyKey     string        `json:"idempotency_key,omitempty"`
	Fingerprint        string        `json:"fingerprint,omitempty"`
	RecoveryQueued     bool          `json:"recovery_queued,omitempty"`
	ReconciliationNote string        `json:"reconciliation_note,omitempty"`
	StartedAt          time.Time     `json:"started_at"`
	UpdatedAt          time.Time     `json:"updated_at"`
}

// Store persists execution records. Production side-effecting operations
// require a Durable store during operation registration.
type Store interface {
	Durable() bool
	Put(context.Context, Record) error
	Get(context.Context, string) (Record, bool, error)
	Reconcile(context.Context, string, core.Outcome, string) (Record, error)
	MarkRecoveryQueued(context.Context, string) (Record, error)
}

// StateFor converts a response into its persisted lifecycle state.
func StateFor(response core.Response) State {
	if response.Outcome == core.OutcomeExecutedUnconfirmed {
		return StateExecutedUnconfirmed
	}
	if response.Allowed {
		return StateAllowed
	}
	return StateDenied
}

func validateRecord(record Record) error {
	if record.ExecutionID == "" {
		return fmt.Errorf("execution: execution_id is required")
	}
	if record.OperationVersion == "" {
		return fmt.Errorf("execution: operation_version is required")
	}
	if record.State == "" {
		return fmt.Errorf("execution: state is required")
	}
	return nil
}

func validateReconciliation(outcome core.Outcome) error {
	if outcome != core.OutcomeAllowed && outcome != core.OutcomeDenied {
		return fmt.Errorf("execution: reconciliation outcome must be allowed or denied")
	}
	return nil
}
