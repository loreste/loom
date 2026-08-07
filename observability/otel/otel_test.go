package otel

import (
	"context"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	loomruntime "github.com/loreste/loom/runtime"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
)

func TestBridgeObservesWithoutSensitiveDimensions(t *testing.T) {
	bridge, err := New(Config{
		Meter:  noop.NewMeterProvider().Meter("test"),
		Tracer: trace.NewNoopTracerProvider().Tracer("test"),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	bridge.Observe(loomruntime.Observation{
		Context:          context.Background(),
		ExecutionID:      "execution-secret-id",
		Principal:        "customer-secret-id",
		Boundary:         "tenant-secret-id",
		Operation:        "customer.read",
		OperationVersion: "1",
		Decision:         core.DecisionDeny,
		Outcome:          core.OutcomeDenied,
		Reason:           core.ReasonBoundaryViolation,
		Step:             "boundary",
		Duration:         10 * time.Millisecond,
	})
}

func TestBoundedDimensions(t *testing.T) {
	if got := bounded(""); got != "unknown" {
		t.Fatalf("empty dimension = %q", got)
	}
	if got := bounded("1234567890"); got != "1234567890" {
		t.Fatalf("normal dimension = %q", got)
	}
	if got := bounded("1234567890" + "1234567890" + "1234567890" + "1234567890" + "1234567890" + "1234567890" + "1234567890" + "1234567890" + "1234567890" + "1234567890"); got != "other" {
		t.Fatalf("oversized dimension = %q", got)
	}
}
