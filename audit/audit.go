// Package audit records every allow and deny. Audit failures must not grant access:
// on deny paths the runtime logs the emit error and still returns the decision;
// on allow paths an emit failure fails closed (the allow becomes a deny).
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/loreste/loom/guardrails"
)

// Event is one immutable audit record.
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	TraceID   string    `json:"trace_id"`
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason,omitempty"`
	Step      string    `json:"step,omitempty"`
	Message   string    `json:"message,omitempty"`
	Principal string    `json:"principal,omitempty"`
	Delegator string    `json:"delegator,omitempty"`
	Boundary  string    `json:"boundary,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Operation string    `json:"operation"`
	Resource  string    `json:"resource,omitempty"`
	Risk      string    `json:"risk,omitempty"`
	// Input is redacted.
	Input map[string]any `json:"input,omitempty"`
	// Metadata is redacted copy of request metadata (no tokens).
	Metadata map[string]string `json:"metadata,omitempty"`
	// DurationMS of pipeline.
	DurationMS int64 `json:"duration_ms"`
	// AuthMethod how principal was verified.
	AuthMethod string `json:"auth_method,omitempty"`
	// PriorAuditID links a replay event to the original execution's audit ID.
	// Serialized by the JSONL (WriterSink) and memory sinks; the Postgres sink
	// schema has no column for it yet, so it is not persisted there.
	PriorAuditID string `json:"prior_audit_id,omitempty"`
}

// Sink persists events.
type Sink interface {
	Write(ctx context.Context, ev Event) error
}

// MemorySink stores events in memory (tests).
type MemorySink struct {
	mu     sync.Mutex
	Events []Event
}

// Durable reports whether audit records survive process restart.
func (m *MemorySink) Durable() bool { return false }

// Write appends an event.
func (m *MemorySink) Write(_ context.Context, ev Event) error {
	if m == nil {
		return fmt.Errorf("audit: nil sink")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, ev)
	return nil
}

// Snapshot returns a copy of events.
func (m *MemorySink) Snapshot() []Event {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.Events))
	copy(out, m.Events)
	return out
}

// WriterSink JSON-encodes events to an io.Writer (stdout, file).
type WriterSink struct {
	mu      sync.Mutex
	w       io.Writer
	enc     *json.Encoder
	durable bool
}

// Durable reports whether the writer is configured. Durability of the target
// is the application's responsibility (for example, a persistent file or
// managed log sink).
func (s *WriterSink) Durable() bool { return s != nil && s.w != nil && s.durable }

// NewWriterSink creates a JSONL sink.
func NewWriterSink(w io.Writer) *WriterSink {
	if w == nil {
		w = os.Stdout
	}
	return &WriterSink{w: w, enc: json.NewEncoder(w)}
}

// NewDurableWriterSink marks a writer whose caller has established durable
// delivery (for example, an fsync-backed file or managed log exporter).
// The sink cannot infer durability from io.Writer alone, so it is opt-in.
func NewDurableWriterSink(w io.Writer) *WriterSink {
	s := NewWriterSink(w)
	s.durable = w != nil
	return s
}

// Write encodes one event as a JSON line.
func (s *WriterSink) Write(_ context.Context, ev Event) error {
	if s == nil {
		return fmt.Errorf("audit: nil sink")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(ev)
}

// MultiSink fans out to multiple sinks; returns first error but attempts all.
type MultiSink struct {
	Sinks []Sink
}

// Durable reports true only when every configured sink is durable. A fan-out
// containing an in-memory sink is still useful for tests, but not sufficient
// for production security-state validation.
func (m *MultiSink) Durable() bool {
	if m == nil || len(m.Sinks) == 0 {
		return false
	}
	for _, sink := range m.Sinks {
		d, ok := sink.(interface{ Durable() bool })
		if !ok || !d.Durable() {
			return false
		}
	}
	return true
}

// Write fans out.
func (m *MultiSink) Write(ctx context.Context, ev Event) error {
	var first error
	for _, s := range m.Sinks {
		if s == nil {
			continue
		}
		if err := s.Write(ctx, ev); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Logger builds and emits events.
type Logger struct {
	Sink Sink
}

// NewLogger wraps a sink.
func NewLogger(sink Sink) *Logger {
	return &Logger{Sink: sink}
}

// Emit writes a redacted event. Never includes credentials or approval tokens.
func (l *Logger) Emit(ctx context.Context, ev Event) (string, error) {
	if ev.ID == "" {
		ev.ID = newID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.Input = guardrails.RedactSecrets(ev.Input)
	ev.Message = guardrails.ScrubString(ev.Message)
	if ev.Metadata != nil {
		md := make(map[string]string, len(ev.Metadata))
		for k, v := range ev.Metadata {
			if isSensitiveMeta(k) {
				md[k] = "[REDACTED]"
			} else {
				md[k] = guardrails.ScrubString(v)
			}
		}
		ev.Metadata = md
	}
	if l == nil || l.Sink == nil {
		return ev.ID, fmt.Errorf("audit: logger not configured")
	}
	return ev.ID, l.Sink.Write(ctx, ev)
}

// isSensitiveMeta matches case-insensitively: an exact set, plus any key
// containing token|secret|key|password|authorization. Over-redaction is safe.
func isSensitiveMeta(k string) bool {
	lk := strings.ToLower(strings.TrimSpace(k))
	switch lk {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-approval-token", "token":
		return true
	}
	for _, frag := range []string{"token", "secret", "key", "password", "authorization"} {
		if strings.Contains(lk, frag) {
			return true
		}
	}
	return false
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}
