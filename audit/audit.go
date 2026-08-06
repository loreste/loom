// Package audit records every allow and deny. Audit failures must not grant access:
// on deny paths the runtime logs the emit error and still returns the decision;
// on allow paths an emit failure fails closed (the allow becomes a deny).
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/guardrails"
)

// Event is one immutable audit record.
type Event struct {
	// SchemaVersion is the audit event schema, independent of protocol version.
	SchemaVersion      int       `json:"schema_version"`
	EventType          string    `json:"event_type"`
	ID                 string    `json:"id"`
	ExecutionID        string    `json:"execution_id,omitempty"`
	ExecutionState     string    `json:"execution_state,omitempty"`
	ExecutionRevision  int64     `json:"execution_revision,omitempty"`
	RecoveryQueued     bool      `json:"recovery_queued,omitempty"`
	ReconciliationNote string    `json:"reconciliation_note,omitempty"`
	Timestamp          time.Time `json:"timestamp"`
	TraceID            string    `json:"trace_id"`
	ProtocolVersion    string    `json:"protocol_version"`
	Decision           string    `json:"decision"`
	Outcome            string    `json:"outcome,omitempty"`
	Reason             string    `json:"reason,omitempty"`
	Step               string    `json:"step,omitempty"`
	Message            string    `json:"message,omitempty"`
	Principal          string    `json:"principal,omitempty"`
	Delegator          string    `json:"delegator,omitempty"`
	Boundary           string    `json:"boundary,omitempty"`
	BoundaryType       string    `json:"boundary_type,omitempty"`
	BoundaryParentType string    `json:"boundary_parent_type,omitempty"`
	BoundaryParentID   string    `json:"boundary_parent_id,omitempty"`
	TenantID           string    `json:"tenant_id,omitempty"`
	Operation          string    `json:"operation"`
	OperationVersion   string    `json:"operation_version,omitempty"`
	Resource           string    `json:"resource,omitempty"`
	ResourceType       string    `json:"resource_type,omitempty"`
	ResourceID         string    `json:"resource_id,omitempty"`
	Effects            []string  `json:"effects,omitempty"`
	Risk               string    `json:"risk,omitempty"`
	// Input is redacted.
	Input               map[string]any `json:"input,omitempty"`
	InputDigest         string         `json:"input_digest,omitempty"`
	OutputDigest        string         `json:"output_digest,omitempty"`
	OutputFieldCount    int            `json:"output_field_count"`
	RequestedFieldCount int            `json:"requested_field_count"`
	// Metadata is redacted copy of request metadata (no tokens).
	Metadata map[string]string `json:"metadata,omitempty"`
	// DurationMS of pipeline.
	DurationMS int64 `json:"duration_ms"`
	// AuthMethod how principal was verified.
	AuthMethod           string `json:"auth_method,omitempty"`
	IdempotencyKeyDigest string `json:"idempotency_key_digest,omitempty"`
	IdempotencyState     string `json:"idempotency_state,omitempty"`
	ApprovalState        string `json:"approval_state,omitempty"`
	QuotaState           string `json:"quota_state,omitempty"`
	ReliabilityWarning   string `json:"reliability_warning,omitempty"`
	Adapter              string `json:"adapter,omitempty"`
	// PriorAuditID links a replay event to the original execution's audit ID.
	// It is persisted by the JSONL, memory, and PostgreSQL sinks.
	PriorAuditID string `json:"prior_audit_id,omitempty"`
	// PrevEventHash and EventHash make an audit stream tamper-evident when the
	// sink is wrapped with HashChainSink. They are empty for unchained events.
	PrevEventHash string `json:"prev_event_hash,omitempty"`
	EventHash     string `json:"event_hash,omitempty"`
}

// Digest returns a stable SHA-256 digest of a redacted JSON value. It lets
// compliance systems correlate payloads without storing unrestricted data.
func Digest(value any) string {
	redacted := value
	if object, ok := value.(map[string]any); ok {
		redacted = guardrails.RedactSecrets(object)
	}
	raw, err := json.Marshal(redacted)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// DigestString returns a SHA-256 digest for an opaque string such as an
// idempotency key. The original value must not be persisted when a digest is enough.
func DigestString(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
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
	m.Events = append(m.Events, cloneEvent(ev))
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
	for i, event := range m.Events {
		out[i] = cloneEvent(event)
	}
	return out
}

func cloneEvent(event Event) Event {
	event.Effects = append([]string(nil), event.Effects...)
	event.Input = cloneMap(event.Input)
	if event.Metadata != nil {
		metadata := make(map[string]string, len(event.Metadata))
		for key, value := range event.Metadata {
			metadata[key] = value
		}
		event.Metadata = metadata
	}
	return event
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
		for i, item := range typed {
			output[i] = cloneValue(item)
		}
		return output
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
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
	if ev.SchemaVersion == 0 {
		ev.SchemaVersion = 1
	}
	if ev.EventType == "" {
		ev.EventType = "execution.decision"
	}
	if ev.ProtocolVersion == "" {
		ev.ProtocolVersion = core.ProtocolVersion
	}
	if ev.ID == "" {
		ev.ID = newID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.Input = guardrails.RedactSecrets(ev.Input)
	if ev.Input != nil && ev.InputDigest == "" {
		ev.InputDigest = Digest(ev.Input)
	}
	ev.Message = guardrails.ScrubString(ev.Message)
	ev.ReconciliationNote = guardrails.ScrubString(ev.ReconciliationNote)
	ev.ReliabilityWarning = guardrails.ScrubString(ev.ReliabilityWarning)
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
	if ev.Adapter == "" && ev.Metadata != nil {
		ev.Adapter = ev.Metadata["adapter"]
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
