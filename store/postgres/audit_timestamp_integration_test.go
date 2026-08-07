package postgres_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/store/postgres"
)

// PostgreSQL TIMESTAMPTZ rounds to microseconds. These values straddle that
// boundary in both directions, which is what broke chain verification on Linux
// where time.Now() carries nanoseconds.
func TestPostgresAuditTimestampSurvivesRoundTrip(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	for _, ns := range []int{0, 1, 499, 500, 501, 999, 456789123, 456789999, 999999999, 999999500} {
		t.Run(time.Duration(ns).String(), func(t *testing.T) {
			stream := "nano-" + time.Now().UTC().Format("20060102150405.000000000") + "-" + time.Duration(ns).String()
			sink := postgres.NewAuditSinkForStream(b.DB, stream)
			ts := time.Date(2026, 8, 7, 12, 0, 0, ns, time.UTC)
			for i := 0; i < 3; i++ {
				if err := sink.Write(ctx, audit.Event{
					ID: stream + "-" + strconv.Itoa(i), Timestamp: ts.Add(time.Duration(i)), Decision: "deny", Operation: "t",
				}); err != nil {
					t.Fatal(err)
				}
			}
			events, err := sink.ExportStream(ctx, stream, 1, 3, "")
			if err != nil {
				t.Fatalf("export failed for ns=%d: %v", ns, err)
			}
			if len(events) != 3 {
				t.Fatalf("got %d events", len(events))
			}
			if events[0].Timestamp.Nanosecond()%1000 != 0 {
				t.Fatalf("stored timestamp retains sub-microsecond precision: %s", events[0].Timestamp)
			}
		})
	}
}
