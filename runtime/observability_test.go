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
	if got := m.Snapshot()["total"]; got != int64(2) {
		t.Fatalf("total = %v", got)
	}
	prom := m.Prometheus()
	for _, want := range []string{
		"loom_execute_total 2",
		"loom_execute_allowed_total 1",
		"loom_execute_denied_total 1",
		"loom_execute_idempotent_replays_total 1",
		`stage="approval"`,
		`reason="approval_required"`,
	} {
		if !strings.Contains(prom, want) {
			t.Fatalf("metrics missing %q:\n%s", want, prom)
		}
	}
}
