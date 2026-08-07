package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/loreste/loom/core"
)

func TestExportStreamRequiresConfiguredSinkAndContiguousRange(t *testing.T) {
	ctx := context.Background()
	if _, err := (*AuditSink)(nil).ExportStream(ctx, "default", 1, 1, ""); !errors.Is(err, core.ErrInvalidArgument) {
		t.Fatalf("nil sink error = %v, want invalid argument", err)
	}
	sink := NewAuditSinkForStream(nil, "default")
	if _, err := sink.ExportStream(ctx, "default", 2, 1, ""); !errors.Is(err, core.ErrInvalidArgument) {
		t.Fatalf("reversed range error = %v, want invalid argument", err)
	}
	if _, err := sink.ExportStream(ctx, "default", 1, maxAuditExportEvents+1, ""); !errors.Is(err, core.ErrInvalidArgument) {
		t.Fatalf("oversized range error = %v, want invalid argument", err)
	}
}
