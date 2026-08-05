package approval

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

// FileEngine persists approval records as JSON (tokens hashed at rest).
// Adversarial: raw tokens never written; file mode 0600; atomic replace.
type FileEngine struct {
	path string
	mu   sync.Mutex
	// in-memory cache mirrored to disk
	tokens map[string]*Record
}

type fileSnapshot struct {
	Tokens map[string]*Record `json:"tokens"`
}

// NewFileEngine opens or creates path.
func NewFileEngine(path string) (*FileEngine, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path required", core.ErrInvalidArgument)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	e := &FileEngine{path: path, tokens: make(map[string]*Record)}
	if err := e.load(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *FileEngine) load() error {
	b, err := os.ReadFile(e.path)
	if err != nil {
		if os.IsNotExist(err) {
			return e.persistLocked()
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	var snap fileSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("approval: corrupt store: %w", err)
	}
	if snap.Tokens == nil {
		snap.Tokens = make(map[string]*Record)
	}
	// drop expired on load
	now := time.Now()
	for k, r := range snap.Tokens {
		if r == nil || now.After(r.ExpiresAt) {
			delete(snap.Tokens, k)
		}
	}
	e.tokens = snap.Tokens
	return nil
}

func (e *FileEngine) persistLocked() error {
	snap := fileSnapshot{Tokens: e.tokens}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := e.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.path)
}

// Issue implements Issuer.
func (e *FileEngine) Issue(token string, principal core.PrincipalID, op string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	if e == nil {
		return fmt.Errorf("%w: nil engine", core.ErrInvalidArgument)
	}
	if token == "" || principal == "" || op == "" {
		return fmt.Errorf("%w: token, principal, operation required", core.ErrInvalidArgument)
	}
	if ttl <= 0 {
		return fmt.Errorf("%w: ttl must be positive", core.ErrInvalidArgument)
	}
	h := hashTok(token)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tokens[h] = &Record{
		TokenHash: h,
		Principal: principal,
		Operation: op,
		Boundary:  boundary,
		ExpiresAt: time.Now().Add(ttl),
		MaxRisk:   maxRisk,
		SingleUse: true,
	}
	return e.persistLocked()
}

// Evaluate implements Engine. It checks the token but never consumes it;
// the runtime calls Consume only after the handler succeeded.
func (e *FileEngine) Evaluate(_ context.Context, id core.Identity, op *core.Operation, risk core.RiskLevel, boundary core.BoundaryID, token string) Decision {
	if op == nil {
		return Decision{Required: true, Approved: false, Message: "nil operation"}
	}
	required := approvalRequired(op, risk)
	if !required {
		return Decision{Required: false, Approved: true, Message: "approval not required"}
	}
	if token == "" {
		return Decision{Required: true, Approved: false, Message: "approval token required"}
	}
	if e == nil {
		return Decision{Required: true, Approved: false, Message: "approval engine not configured"}
	}
	h := hashTok(token)
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.tokens[h]
	if !ok {
		return Decision{Required: true, Approved: false, Message: "unknown approval token"}
	}
	if !rec.Consumed && time.Now().After(rec.ExpiresAt) {
		delete(e.tokens, h)
		_ = e.persistLocked()
		return Decision{Required: true, Approved: false, Message: "approval token expired"}
	}
	if msg := checkRecord(rec, id, op, boundary, risk); msg != "" {
		return Decision{Required: true, Approved: false, Message: msg}
	}
	return Decision{Required: true, Approved: true, Message: "approval token accepted"}
}

// Consume implements Engine. Burns the single-use token and persists.
// Fail closed: if the persist fails, the in-memory burn is rolled back and an
// error returned, so the token is not silently replayable after restart.
func (e *FileEngine) Consume(_ context.Context, id core.Identity, op *core.Operation, boundary core.BoundaryID, token string) error {
	if e == nil {
		return fmt.Errorf("%w: nil engine", core.ErrInvalidArgument)
	}
	if token == "" || op == nil {
		return fmt.Errorf("%w: token and operation required", core.ErrInvalidArgument)
	}
	h := hashTok(token)
	e.mu.Lock()
	defer e.mu.Unlock()
	rec, ok := e.tokens[h]
	if !ok {
		return fmt.Errorf("approval: unknown token")
	}
	if msg := checkRecord(rec, id, op, boundary, rec.MaxRisk); msg != "" {
		return fmt.Errorf("approval: %s", msg)
	}
	if rec.SingleUse {
		rec.Consumed = true
		if err := e.persistLocked(); err != nil {
			rec.Consumed = false
			return fmt.Errorf("approval: consume persist failed: %w", err)
		}
	}
	return nil
}

// Count returns non-expired records (ops/metrics).
func (e *FileEngine) Count() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	now := time.Now()
	for _, r := range e.tokens {
		if r != nil && !now.After(r.ExpiresAt) {
			n++
		}
	}
	return n
}

var _ Store = (*FileEngine)(nil)
