package idempotency

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

// FileStore persists idempotency records as a single JSON file (0600).
// Suitable for single-node serve; not for multi-writer without external lock.
type FileStore struct {
	path string
	mu   sync.Mutex
	data map[string]*entry
}

// Durable reports whether idempotency state survives process restart.
func (s *FileStore) Durable() bool { return s != nil }

type fileSnap struct {
	Entries map[string]*persistedEntry `json:"entries"`
}

type persistedEntry struct {
	Fingerprint string         `json:"fingerprint"`
	Response    *core.Response `json:"response,omitempty"`
	InFlight    bool           `json:"in_flight"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

// NewFileStore opens or creates path.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path required", core.ErrInvalidArgument)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &FileStore{path: path, data: make(map[string]*entry)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.persistLocked()
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	var snap fileSnap
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("idempotency: corrupt store: %w", err)
	}
	now := time.Now()
	s.data = make(map[string]*entry)
	for k, pe := range snap.Entries {
		if pe == nil || now.After(pe.ExpiresAt) {
			continue
		}
		// Drop abandoned in-flight on restart (fail closed: allow retry).
		if pe.InFlight && pe.Response == nil {
			continue
		}
		s.data[k] = &entry{
			fingerprint: pe.Fingerprint,
			response:    pe.Response,
			inFlight:    false,
			expiresAt:   pe.ExpiresAt,
		}
	}
	return nil
}

func (s *FileStore) persistLocked() error {
	snap := fileSnap{Entries: make(map[string]*persistedEntry, len(s.data))}
	for k, e := range s.data {
		snap.Entries[k] = &persistedEntry{
			Fingerprint: e.fingerprint,
			Response:    e.response,
			InFlight:    e.inFlight,
			ExpiresAt:   e.expiresAt,
		}
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *FileStore) Get(_ context.Context, key string) (*Stored, bool, error) {
	if s == nil || key == "" {
		return nil, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return nil, false, nil
	}
	if time.Now().After(e.expiresAt) {
		delete(s.data, key)
		_ = s.persistLocked()
		return nil, false, nil
	}
	if e.inFlight || e.response == nil {
		return nil, false, nil
	}
	cp := cloneResponse(*e.response)
	return &Stored{Fingerprint: e.fingerprint, Response: cp, ExpiresAt: e.expiresAt}, true, nil
}

func (s *FileStore) PutIfAbsent(_ context.Context, key string, st *Stored) error {
	if s == nil {
		return fmt.Errorf("%w: nil store", core.ErrInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[key]; ok && time.Now().Before(e.expiresAt) {
		if e.fingerprint != st.Fingerprint {
			return fmt.Errorf("%w: idempotency key conflict", core.ErrAlreadyExists)
		}
		return nil
	}
	resp := cloneResponse(st.Response)
	s.data[key] = &entry{fingerprint: st.Fingerprint, response: &resp, expiresAt: st.ExpiresAt}
	return s.persistLocked()
}

func (s *FileStore) Begin(_ context.Context, key, fingerprint string, ttl time.Duration) error {
	if s == nil || key == "" {
		return fmt.Errorf("%w: key required", core.ErrInvalidArgument)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[key]; ok && time.Now().Before(e.expiresAt) {
		if e.fingerprint != fingerprint {
			return fmt.Errorf("%w: idempotency key conflict", core.ErrAlreadyExists)
		}
		if e.response != nil {
			return fmt.Errorf("%w: already completed", core.ErrAlreadyExists)
		}
		if e.inFlight {
			return fmt.Errorf("%w: in flight", core.ErrAlreadyExists)
		}
	}
	s.data[key] = &entry{
		fingerprint: fingerprint,
		inFlight:    true,
		expiresAt:   time.Now().Add(ttl),
	}
	return s.persistLocked()
}

func (s *FileStore) Complete(_ context.Context, key string, st *Stored) error {
	if s == nil {
		return fmt.Errorf("%w: nil store", core.ErrInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return fmt.Errorf("%w: key not begun", core.ErrNotFound)
	}
	if e.fingerprint != st.Fingerprint {
		return fmt.Errorf("%w: fingerprint mismatch", core.ErrAlreadyExists)
	}
	resp := cloneResponse(st.Response)
	e.response = &resp
	e.inFlight = false
	e.expiresAt = st.ExpiresAt
	return s.persistLocked()
}

func (s *FileStore) Abort(_ context.Context, key string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return nil
	}
	if e.inFlight && e.response == nil {
		delete(s.data, key)
		return s.persistLocked()
	}
	return nil
}

var _ Store = (*FileStore)(nil)
