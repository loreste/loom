package execution

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// MemoryStore is intended for development and tests. It is not durable.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (*MemoryStore) Durable() bool { return false }

func (s *MemoryStore) Put(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRecord(record); err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("execution: nil memory store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.StartedAt.IsZero() {
		record.StartedAt = time.Now().UTC()
	}
	record.UpdatedAt = time.Now().UTC()
	s.records[record.ExecutionID] = record
	return nil
}

func (s *MemoryStore) Get(ctx context.Context, id string) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	if s == nil || id == "" {
		return Record{}, false, fmt.Errorf("execution: execution_id is required")
	}
	s.mu.RLock()
	record, ok := s.records[id]
	s.mu.RUnlock()
	return record, ok, nil
}

func (s *MemoryStore) Reconcile(ctx context.Context, id string, outcome core.Outcome, note string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if err := validateReconciliation(outcome); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, fmt.Errorf("execution: %s not found", id)
	}
	if record.State != StateExecutedUnconfirmed && record.State != StateReconciled {
		return Record{}, fmt.Errorf("execution: %s is not awaiting reconciliation", id)
	}
	record.Outcome = outcome
	record.State = StateReconciled
	record.Response.Outcome = outcome
	record.Response.Allowed = outcome == core.OutcomeAllowed
	record.Response.ReliabilityWarning = ""
	record.ReconciliationNote = note
	record.UpdatedAt = time.Now().UTC()
	s.records[id] = record
	return record, nil
}

func (s *MemoryStore) MarkRecoveryQueued(ctx context.Context, id string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return Record{}, fmt.Errorf("execution: %s not found", id)
	}
	record.RecoveryQueued = true
	record.UpdatedAt = time.Now().UTC()
	s.records[id] = record
	return record, nil
}
