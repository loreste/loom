package runtime

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Observation is emitted once for every Runtime.Execute call. Observers are
// deliberately small so applications can bridge Loom to OpenTelemetry,
// Prometheus, or their existing metrics system without adding a dependency to
// the security core.
type Observation struct {
	Operation        string
	Boundary         core.BoundaryID
	Principal        core.PrincipalID
	Decision         core.Decision
	Reason           string
	Step             string
	Duration         time.Duration
	IdempotentReplay bool
}

// Observer receives execution observations. Implementations must not panic;
// Runtime recovers from observer panics as a final fail-closed safeguard.
type Observer interface {
	Observe(Observation)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(Observation)

func (f ObserverFunc) Observe(o Observation) {
	if f != nil {
		f(o)
	}
}

// Metrics is a dependency-free metrics collector suitable for a /metrics
// endpoint or as one input to an OpenTelemetry/Prometheus bridge.
type Metrics struct {
	mu                   sync.RWMutex
	total                int64
	allowed              int64
	denied               int64
	duration             time.Duration
	replays              int64
	approvalRequired     int64
	quotaRejected        int64
	idempotencyConflicts int64
	byStage              map[string]int64
	byReason             map[string]int64
}

// NewMetrics creates an empty collector.
func NewMetrics() *Metrics {
	return &Metrics{byStage: make(map[string]int64), byReason: make(map[string]int64)}
}

// Observe implements Observer.
func (m *Metrics) Observe(o Observation) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	if o.Decision == core.DecisionAllow {
		m.allowed++
		if o.IdempotentReplay {
			m.replays++
		}
	} else {
		m.denied++
		switch o.Reason {
		case core.ReasonApprovalRequired:
			m.approvalRequired++
		case core.ReasonQuotaExceeded:
			m.quotaRejected++
		case core.ReasonIdempotencyConflict:
			m.idempotencyConflicts++
		}
	}
	m.duration += o.Duration
	if o.Step == "" {
		o.Step = "unknown"
	}
	if o.Reason == "" {
		o.Reason = "none"
	}
	m.byStage[o.Step]++
	m.byReason[o.Reason]++
}

// Snapshot returns stable counters for dashboards and tests.
func (m *Metrics) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"total":                 m.total,
		"allowed":               m.allowed,
		"denied":                m.denied,
		"duration_seconds":      m.duration.Seconds(),
		"idempotent_replays":    m.replays,
		"approval_required":     m.approvalRequired,
		"quota_rejected":        m.quotaRejected,
		"idempotency_conflicts": m.idempotencyConflicts,
	}
}

// Prometheus renders the collector in the Prometheus text exposition format.
// Labels are fixed to the stage/reason dimensions and sanitized before output.
func (m *Metrics) Prometheus() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var b strings.Builder
	b.WriteString("# HELP loom_execute_total Governed execution attempts.\n")
	b.WriteString("# TYPE loom_execute_total counter\n")
	fmt.Fprintf(&b, "loom_execute_total %d\n", m.total)
	b.WriteString("# HELP loom_execute_allowed_total Governed executions that completed successfully.\n")
	b.WriteString("# TYPE loom_execute_allowed_total counter\n")
	fmt.Fprintf(&b, "loom_execute_allowed_total %d\n", m.allowed)
	b.WriteString("# HELP loom_execute_denied_total Governed executions denied by the pipeline.\n")
	b.WriteString("# TYPE loom_execute_denied_total counter\n")
	fmt.Fprintf(&b, "loom_execute_denied_total %d\n", m.denied)
	b.WriteString("# HELP loom_execute_duration_seconds_total Cumulative execution duration.\n")
	b.WriteString("# TYPE loom_execute_duration_seconds_total counter\n")
	fmt.Fprintf(&b, "loom_execute_duration_seconds_total %f\n", m.duration.Seconds())
	fmt.Fprintf(&b, "loom_execute_idempotent_replays_total %d\n", m.replays)
	fmt.Fprintf(&b, "loom_execute_approval_required_total %d\n", m.approvalRequired)
	fmt.Fprintf(&b, "loom_execute_quota_rejected_total %d\n", m.quotaRejected)
	fmt.Fprintf(&b, "loom_execute_idempotency_conflicts_total %d\n", m.idempotencyConflicts)

	keys := make([]string, 0, len(m.byStage))
	for key := range m.byStage {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	b.WriteString("# TYPE loom_execute_stage_total counter\n")
	for _, key := range keys {
		fmt.Fprintf(&b, "loom_execute_stage_total{stage=%q} %d\n", sanitizeLabel(key), m.byStage[key])
	}
	keys = keys[:0]
	for key := range m.byReason {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	b.WriteString("# TYPE loom_execute_reason_total counter\n")
	for _, key := range keys {
		fmt.Fprintf(&b, "loom_execute_reason_total{reason=%q} %d\n", sanitizeLabel(key), m.byReason[key])
	}
	return b.String()
}

func sanitizeLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' {
			return '-'
		}
		return r
	}, s)
}
