package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/store/postgres"
)

func TestPostgresAuditExportVerifiesContiguousSegment(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	stream := "export-" + time.Now().UTC().Format("20060102150405.000000000")
	sink := postgres.NewAuditSinkForStream(b.DB, stream)
	for i := 0; i < 3; i++ {
		if err := sink.Write(ctx, audit.Event{
			ID:        stream + "-" + string(rune('a'+i)),
			Timestamp: time.Now().UTC(),
			Decision:  "deny",
			Operation: "audit.export.test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := sink.ExportStream(ctx, stream, 1, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Sequence != 1 || events[2].Sequence != 3 {
		t.Fatalf("exported events = %+v", events)
	}
	if _, err := b.DB.ExecContext(ctx,
		`UPDATE loom_audit SET event_hash = 'tampered' WHERE audit_stream = $1 AND sequence_no = 2`, stream); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.ExportStream(ctx, stream, 1, 3, ""); err == nil {
		t.Fatal("tampered audit segment unexpectedly verified")
	}
}
