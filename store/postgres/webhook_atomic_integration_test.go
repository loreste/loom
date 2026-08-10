package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/store/postgres"
)

// TestPostgresAuditWriteAtomicallyEnqueuesWebhook proves that enabling the
// webhook outbox on the audit sink inserts both rows under one commit: a
// rolled-back failure path cannot leave a webhook row without audit.
func TestPostgresAuditWriteAtomicallyEnqueuesWebhook(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	stream := "atomic-webhook-" + time.Now().UTC().Format("20060102150405.000000000")
	sink := postgres.NewAuditSinkForStream(b.DB, stream)
	sink.EnableWebhookOutbox()

	ev := audit.Event{
		ID:            "audit-atomic-1-" + stream,
		SchemaVersion: 1,
		EventType:     "execution.decision",
		Timestamp:     time.Now().UTC(),
		TraceID:       "trace-1",
		Decision:      "allow",
		Outcome:       string(core.OutcomeAllowed),
		Operation:     "payment.capture",
	}
	if err := sink.Write(ctx, ev); err != nil {
		t.Fatal(err)
	}

	var auditCount, outboxCount int
	if err := b.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM loom_audit WHERE id = $1`, ev.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := b.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM loom_webhook_outbox WHERE event_id = $1`, ev.ID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || outboxCount != 1 {
		t.Fatalf("audit=%d outbox=%d, want both 1 (atomic enqueue)", auditCount, outboxCount)
	}

	// Idempotent re-enqueue on duplicate event_id must not create a second row.
	// Direct outbox Enqueue after audit Write is a separate path; re-Write same
	// id fails closed on audit conflict without leaving an extra outbox row.
	if err := sink.Write(ctx, ev); err == nil {
		t.Fatal("duplicate audit id must fail closed")
	}
	if err := b.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM loom_webhook_outbox WHERE event_id = $1`, ev.ID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("outbox count after failed re-write = %d, want 1", outboxCount)
	}
}
