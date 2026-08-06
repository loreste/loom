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
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
	if _, existed := s.records[record.ExecutionID]; existed {
		return fmt.Errorf("%w: execution %s already exists", core.ErrAlreadyExists, record.ExecutionID)
	}
	s.records[record.ExecutionID] = cloneRecord(record)
	if err := s.persistLocked(); err != nil {
		delete(s.records, record.ExecutionID)
		return err
	}
	return nil
}

func (s *FileStore) Complete(ctx context.Context, updated Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("execution: nil file store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.records[updated.ExecutionID]
	if !ok {
		return fmt.Errorf("%w: execution %s", core.ErrNotFound, updated.ExecutionID)
	}
	completed, err := CompleteRecord(previous, updated)
	if err != nil {
		return err
	}
	s.records[updated.ExecutionID] = completed
	if err := s.persistLocked(); err != nil {
		s.records[updated.ExecutionID] = previous
		return err
	}
	return nil
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
	return cloneRecord(record), ok, nil
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
	updated, err := reconcileRecord(record, outcome, note)
	if err != nil {
		return Record{}, err
	}
	if record.State == StateReconciled {
		return updated, nil
	}
	s.records[id] = cloneRecord(updated)
	if err := s.persistLocked(); err != nil {
		s.records[id] = record
		return Record{}, err
	}
	return cloneRecord(updated), nil
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
	previous := s.records[id]
	s.records[id] = cloneRecord(record)
	if err := s.persistLocked(); err != nil {
		s.records[id] = previous
		return Record{}, err
	}
	return cloneRecord(record), nil
}
