package runtime_test

import (
	"strings"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

func TestMetricsPrometheusAndSnapshot(t *testing.T) {
	m := runtime.NewMetrics()
	m.Begin()
	if got := m.Snapshot()["active_executions"]; got != int64(1) {
		t.Fatalf("active_executions = %v", got)
	}
	m.ObserveDurableStore(10*time.Millisecond, false)
	m.ObserveDurableStore(5*time.Millisecond, true)
	m.ObserveRecoveryQueue(3, 2*time.Minute)
	m.ObserveRecoveryProgress(2, 4, 1)
	// A worker reporting progress must not reset the gauges a queue sample set.
	m.ObserveRecoveryProgress(1, 0, 0)
	m.Observe(runtime.Observation{Decision: core.DecisionAllow, Step: "execute", Reason: "allow", IdempotentReplay: true, Duration: 2 * time.Millisecond})
	m.Observe(runtime.Observation{Decision: core.DecisionDeny, Step: "approval", Reason: core.ReasonApprovalRequired, Duration: 20 * time.Millisecond})
	m.Observe(runtime.Observation{Decision: core.DecisionDeny, Outcome: core.OutcomeExecutedUnconfirmed, Step: "audit", Reason: core.ReasonExecutedUnconfirmed, Duration: 2 * time.Second})
	if got := m.Snapshot()["total"]; got != int64(3) {
		t.Fatalf("total = %v", got)
	}
	if got := m.Snapshot()["executed_unconfirmed"]; got != int64(1) {
		t.Fatalf("executed_unconfirmed = %v", got)
	}
	snapshot := m.Snapshot()
	if got := snapshot["durable_store_errors"]; got != int64(1) {
		t.Fatalf("durable_store_errors = %v", got)
	}
	if got := snapshot["recovery_depth"]; got != int64(3) {
		t.Fatalf("recovery_depth = %v", got)
	}
	prom := m.Prometheus()
	for _, want := range []string{
		"loom_execute_total 3",
		"loom_execute_allowed_total 1",
		"loom_execute_denied_total 2",
		"loom_execute_executed_unconfirmed_total 1",
		"loom_execute_idempotent_replays_total 1",
		`loom_execute_duration_seconds_bucket{le="0.005"} 1`,
		"loom_execute_duration_seconds_sum ",
		"loom_execute_duration_seconds_count 3",
		"loom_recovery_attempts_total 3",
		"loom_durable_store_errors_total 1",
		"loom_recovery_depth 3",
		`stage="approval"`,
		`reason="approval_required"`,
	} {
		if !strings.Contains(prom, want) {
			t.Fatalf("metrics missing %q:\n%s", want, prom)
		}
	}
	m.End()
	if got := m.Snapshot()["active_executions"]; got != int64(0) {
		t.Fatalf("active_executions after End = %v", got)
	}
}
