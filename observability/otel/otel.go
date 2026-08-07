// Package otel provides Loom's maintained OpenTelemetry observer bridge.
//
// The bridge records bounded execution metrics and annotates the current span
// when the request context already carries one. It deliberately omits
// execution IDs, principals, boundaries, credentials, request data, and other
// high-cardinality or sensitive values.
package otel

import (
	"context"
	"strings"

	"github.com/loreste/loom/core"
	loomruntime "github.com/loreste/loom/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const instrumentationName = "github.com/loreste/loom/observability/otel"

// Config supplies application-owned OpenTelemetry providers. Nil providers
// use the process-wide OpenTelemetry providers, so applications can configure
// exporters without coupling Loom to a particular collector.
type Config struct {
	Meter  metric.Meter
	Tracer trace.Tracer
}

// Bridge implements runtime.Observer.
type Bridge struct {
	executions metric.Int64Counter
	active     metric.Int64UpDownCounter
	duration   metric.Float64Histogram
	denials    metric.Int64Counter
	uncertain  metric.Int64Counter
	tracer     trace.Tracer
}

// New constructs an OpenTelemetry bridge using the supplied providers.
func New(config Config) (*Bridge, error) {
	meter := config.Meter
	if meter == nil {
		meter = otel.Meter(instrumentationName)
	}
	tracer := config.Tracer
	if tracer == nil {
		tracer = otel.Tracer(instrumentationName)
	}
	executions, err := meter.Int64Counter(
		"loom.executions",
		metric.WithDescription("Governed Loom execution attempts."),
	)
	if err != nil {
		return nil, err
	}
	active, err := meter.Int64UpDownCounter(
		"loom.active_executions",
		metric.WithDescription("In-flight governed Loom executions."),
	)
	if err != nil {
		return nil, err
	}
	duration, err := meter.Float64Histogram(
		"loom.execution.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Governed Loom execution duration in seconds."),
	)
	if err != nil {
		return nil, err
	}
	denials, err := meter.Int64Counter(
		"loom.denials",
		metric.WithDescription("Governed Loom denials."),
	)
	if err != nil {
		return nil, err
	}
	uncertain, err := meter.Int64Counter(
		"loom.executed_unconfirmed",
		metric.WithDescription("Executions whose side effect is not yet confirmed."),
	)
	if err != nil {
		return nil, err
	}
	return &Bridge{
		executions: executions,
		active:     active,
		duration:   duration,
		denials:    denials,
		uncertain:  uncertain,
		tracer:     tracer,
	}, nil
}

func (b *Bridge) Begin() {
	if b != nil {
		b.active.Add(context.Background(), 1)
	}
}

func (b *Bridge) End() {
	if b != nil {
		b.active.Add(context.Background(), -1)
	}
}

// Observe records one final execution observation. It does not create a new
// span after the operation; when a caller already supplied a trace context,
// it annotates that span instead.
func (b *Bridge) Observe(observation loomruntime.Observation) {
	if b == nil {
		return
	}
	ctx := observation.Context
	if ctx == nil {
		ctx = context.Background()
	}
	attrs := metricAttributes(observation)
	b.executions.Add(ctx, 1, metric.WithAttributes(attrs...))
	b.duration.Record(ctx, observation.Duration.Seconds(), metric.WithAttributes(attrs...))
	if observation.Decision != core.DecisionAllow {
		b.denials.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	if observation.Outcome == core.OutcomeExecutedUnconfirmed {
		b.uncertain.Add(ctx, 1, metric.WithAttributes(attrs...))
	}

	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	span.SetAttributes(
		attribute.String("loom.operation", bounded(observation.Operation)),
		attribute.String("loom.operation_version", bounded(observation.OperationVersion)),
		attribute.String("loom.adapter", bounded(observation.Adapter)),
		attribute.String("loom.decision", observation.Decision.String()),
		attribute.String("loom.outcome", bounded(string(observation.Outcome))),
		attribute.String("loom.reason", bounded(observation.Reason)),
		attribute.String("loom.stage", bounded(observation.Step)),
	)
}

func metricAttributes(observation loomruntime.Observation) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("operation", bounded(observation.Operation)),
		attribute.String("operation_version", bounded(observation.OperationVersion)),
		attribute.String("adapter", bounded(observation.Adapter)),
		attribute.String("decision", observation.Decision.String()),
		attribute.String("outcome", bounded(string(observation.Outcome))),
		attribute.String("reason", bounded(observation.Reason)),
		attribute.String("stage", bounded(observation.Step)),
	}
}

func bounded(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	if len(value) > 96 {
		return "other"
	}
	return value
}
