// Package idempotency provides safe retry semantics.
// Same key + same request fingerprint ⇒ replay stored response.
// Same key + different fingerprint ⇒ conflict (deny).
package idempotency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Stored is a cached successful (or terminal) response.
type Stored struct {
	Fingerprint string
	Response    core.Response
	StoredAt    time.Time
	ExpiresAt   time.Time
}

// Store is the idempotency backend.
type Store interface {
	// Get returns stored value if present and not expired.
	Get(ctx context.Context, key string) (*Stored, bool, error)
	// PutIfAbsent stores if key free or same fingerprint. Conflict if different fingerprint.
	PutIfAbsent(ctx context.Context, key string, s *Stored) error
	// Begin reserves a key as in-flight. Returns ErrAlreadyExists if reserved/completed.
	Begin(ctx context.Context, key, fingerprint string, ttl time.Duration) error
	// Complete finalizes an in-flight key with the response.
	Complete(ctx context.Context, key string, s *Stored) error
	// Abort releases in-flight reservation on failure (allows retry).
	Abort(ctx context.Context, key string) error
}

// MemoryStore is a process-local store with TTL eviction on read.
type MemoryStore struct {
	mu   sync.Mutex
	data map[string]*entry
}

// Durable reports whether idempotency state survives process restart.
func (s *MemoryStore) Durable() bool { return false }

type entry struct {
	fingerprint string
	response    *core.Response
	inFlight    bool
	expiresAt   time.Time
}

// NewMemoryStore creates an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string]*entry)}
}

func (s *MemoryStore) Get(_ context.Context, key string) (*Stored, bool, error) {
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
		return nil, false, nil
	}
	if e.inFlight || e.response == nil {
		return nil, false, nil
	}
	cp := cloneResponse(*e.response)
	return &Stored{Fingerprint: e.fingerprint, Response: cp, ExpiresAt: e.expiresAt}, true, nil
}

func (s *MemoryStore) PutIfAbsent(_ context.Context, key string, st *Stored) error {
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
	s.data[key] = &entry{
		fingerprint: st.Fingerprint,
		response:    &resp,
		expiresAt:   st.ExpiresAt,
	}
	return nil
}

func (s *MemoryStore) Begin(_ context.Context, key, fingerprint string, ttl time.Duration) error {
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
	return nil
}

func (s *MemoryStore) Complete(_ context.Context, key string, st *Stored) error {
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
	return nil
}

func (s *MemoryStore) Abort(_ context.Context, key string) error {
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
	}
	return nil
}

// Fingerprint hashes stable request identity for conflict detection.
// Excludes TraceID and non-authoritative metadata that may differ per retry.
func Fingerprint(req *core.Request) (string, error) {
	if req == nil {
		return "", fmt.Errorf("%w: nil request", core.ErrInvalidArgument)
	}
	payload := struct {
		Operation string
		Boundary  core.BoundaryID
		Resource  *core.ResourceRef
		Input     map[string]any
		Fields    []string
	}{
		Operation: req.Operation,
		Boundary:  req.Boundary,
		Resource:  req.Resource,
		Input:     req.Input,
		Fields:    req.Fields,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// CompositeKey builds a storage key scoped by principal + boundary + op + client key.
// Prevents cross-principal key collision / theft.
func CompositeKey(principal core.PrincipalID, boundary core.BoundaryID, op, clientKey string) string {
	return string(principal) + "|" + string(boundary) + "|" + op + "|" + clientKey
}

// DefaultTTL when op does not specify.
const DefaultTTL = time.Hour

// cloneResponse deep-copies a Response so stored/replayed Output maps are never
// aliased with caller memory (caller mutation must not corrupt stored replays).
func cloneResponse(r core.Response) core.Response {
	r.Output = cloneOutput(r.Output)
	return r
}

func cloneOutput(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneOutput(t)
	case []any:
		cp := make([]any, len(t))
		for i, e := range t {
			cp[i] = cloneValue(e)
		}
		return cp
	default:
		return v
	}
}
