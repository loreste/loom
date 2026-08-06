package runtime_test

import (
	"strings"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

func TestMetricsPrometheusAndSnapshot(t *testing.T) {
	m := runtime.NewMetrics()
	m.Observe(runtime.Observation{Decision: core.DecisionAllow, Step: "execute", Reason: "allow", IdempotentReplay: true})
	m.Observe(runtime.Observation{Decision: core.DecisionDeny, Step: "approval", Reason: core.ReasonApprovalRequired})
	m.Observe(runtime.Observation{Decision: core.DecisionDeny, Outcome: core.OutcomeExecutedUnconfirmed, Step: "audit", Reason: core.ReasonExecutedUnconfirmed})
	if got := m.Snapshot()["total"]; got != int64(3) {
		t.Fatalf("total = %v", got)
	}
	if got := m.Snapshot()["executed_unconfirmed"]; got != int64(1) {
		t.Fatalf("executed_unconfirmed = %v", got)
	}
	prom := m.Prometheus()
	for _, want := range []string{
		"loom_execute_total 3",
		"loom_execute_allowed_total 1",
		"loom_execute_denied_total 2",
		"loom_execute_executed_unconfirmed_total 1",
		"loom_execute_idempotent_replays_total 1",
		`stage="approval"`,
		`reason="approval_required"`,
	} {
		if !strings.Contains(prom, want) {
			t.Fatalf("metrics missing %q:\n%s", want, prom)
		}
	}
}
