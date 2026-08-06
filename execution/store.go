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

// RecoveryLease is a time-bounded claim on an execution whose durable
// completion record still needs asynchronous recovery.
type RecoveryLease struct {
	Record    Record
	Owner     string
	LeaseID   string
	ExpiresAt time.Time
}

// RecoveryQueue is implemented by stores that can coordinate recovery work
// across workers. ClaimRecovery must return at most one live lease for a
// record; ReleaseRecovery keeps the item queued when completed is false.
type RecoveryQueue interface {
	ClaimRecovery(context.Context, string, time.Duration) (RecoveryLease, bool, error)
	ReleaseRecovery(context.Context, string, string, bool) error
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

// cloneRecord protects store state from callers mutating reference-backed
// response values after Put or Get. Execution output is JSON-shaped, so maps
// and slices are copied recursively without changing scalar types.
func cloneRecord(record Record) Record {
	record.Response.Output = cloneMap(record.Response.Output)
	if record.Response.Denial != nil {
		denial := *record.Response.Denial
		if denial.Details != nil {
			denial.Details = make(map[string]string, len(denial.Details))
			for key, value := range record.Response.Denial.Details {
				denial.Details[key] = value
			}
		}
		record.Response.Denial = &denial
	}
	return record
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = cloneValue(value)
	}
	return output
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		output := make([]any, len(typed))
		for index, item := range typed {
			output[index] = cloneValue(item)
		}
		return output
	case []string:
		return append([]string(nil), typed...)
	case []map[string]any:
		output := make([]map[string]any, len(typed))
		for index, item := range typed {
			output[index] = cloneMap(item)
		}
		return output
	default:
		return value
	}
}

func reconcileRecord(record Record, outcome core.Outcome, note string) (Record, error) {
	if record.State == StateReconciled {
		if record.Outcome != outcome {
			return Record{}, fmt.Errorf("%w: execution %s already reconciled with outcome %s", core.ErrAlreadyExists, record.ExecutionID, record.Outcome)
		}
		return cloneRecord(record), nil
	}
	if record.State != StateExecutedUnconfirmed {
		return Record{}, fmt.Errorf("execution: %s is not awaiting reconciliation", record.ExecutionID)
	}
	record.Outcome = outcome
	record.State = StateReconciled
	record.Response.Outcome = outcome
	record.Response.Allowed = outcome == core.OutcomeAllowed
	record.Response.ReliabilityWarning = ""
	record.ReconciliationNote = note
	record.UpdatedAt = time.Now().UTC()
	return cloneRecord(record), nil
}
