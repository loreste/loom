package webhook

import (
	"context"
	"fmt"
	"strings"

	"github.com/loreste/loom/audit"
)

// OutboxSink is a durable audit.Sink: Write only persists the event to the
// outbox. HTTP delivery is the worker's job. Enqueue failure is the only
// failure mode that can affect the audit pipeline; delivery errors never
// reverse a completed business side effect.
type OutboxSink struct {
	Outbox Outbox
	Filter func(audit.Event) bool
}

// NewOutboxSink wraps an outbox as an audit sink.
func NewOutboxSink(outbox Outbox) (*OutboxSink, error) {
	if outbox == nil {
		return nil, fmt.Errorf("webhook: outbox is required")
	}
	return &OutboxSink{Outbox: outbox}, nil
}

// Durable reports true: the outbox is the durability boundary for delivery work.
func (s *OutboxSink) Durable() bool { return true }

// Write enqueues the event. It does not perform HTTP I/O.
func (s *OutboxSink) Write(ctx context.Context, ev audit.Event) error {
	if s == nil || s.Outbox == nil {
		return fmt.Errorf("webhook: outbox sink is not configured")
	}
	if s.Filter != nil && !s.Filter(ev) {
		return nil
	}
	eventID := strings.TrimSpace(ev.ID)
	if eventID == "" {
		eventID = newEventID()
		ev.ID = eventID
	}
	return s.Outbox.Enqueue(ctx, OutboxRecord{
		EventID:     eventID,
		AuditStream: strings.TrimSpace(ev.AuditStream),
		Sequence:    ev.Sequence,
		Event:       ev,
		State:       StatePending,
	})
}
