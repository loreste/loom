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
	s.records[record.ExecutionID] = cloneRecord(record)
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
	return cloneRecord(record), ok, nil
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
	updated, err := reconcileRecord(record, outcome, note)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateReconciled {
		s.records[id] = cloneRecord(updated)
	}
	return cloneRecord(updated), nil
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
	s.records[id] = cloneRecord(record)
	return cloneRecord(record), nil
}
