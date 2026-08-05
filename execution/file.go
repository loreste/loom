package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// FileStore is a single-node durable execution store. It uses an atomic
// replace and 0600 permissions; distributed deployments should provide a
// shared database-backed implementation.
type FileStore struct {
	mu      sync.Mutex
	path    string
	records map[string]Record
}

func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("execution: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &FileStore{path: path, records: make(map[string]Record)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (*FileStore) Durable() bool { return true }

func (s *FileStore) load() error {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s.persistLocked()
	}
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, &s.records); err != nil {
		return fmt.Errorf("execution: corrupt store: %w", err)
	}
	if s.records == nil {
		s.records = make(map[string]Record)
	}
	return nil
}

func (s *FileStore) persistLocked() error {
	b, err := json.Marshal(s.records)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileStore) Put(ctx context.Context, record Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRecord(record); err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("execution: nil file store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.StartedAt.IsZero() {
		record.StartedAt = time.Now().UTC()
	}
	record.UpdatedAt = time.Now().UTC()
	s.records[record.ExecutionID] = record
	return s.persistLocked()
}

func (s *FileStore) Get(ctx context.Context, id string) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	if s == nil || id == "" {
		return Record{}, false, fmt.Errorf("execution: execution_id is required")
	}
	s.mu.Lock()
	record, ok := s.records[id]
	s.mu.Unlock()
	return record, ok, nil
}

func (s *FileStore) Reconcile(ctx context.Context, id string, outcome core.Outcome, note string) (Record, error) {
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
	if err := s.persistLocked(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *FileStore) MarkRecoveryQueued(ctx context.Context, id string) (Record, error) {
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
	if err := s.persistLocked(); err != nil {
		return Record{}, err
	}
	return record, nil
}
