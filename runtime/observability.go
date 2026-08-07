package runtime

import (
	"context"
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
	// Context carries the request context to maintained telemetry bridges. It
	// is never serialized or used as an authorization input.
	Context            context.Context
	ExecutionID        string
	TraceID            string
	Operation          string
	OperationVersion   string
	Boundary           core.BoundaryID
	Principal          core.PrincipalID
	Decision           core.Decision
	Outcome            core.Outcome
	Reason             string
	Step               string
	Duration           time.Duration
	IdempotentReplay   bool
	AuditID            string
	ReliabilityWarning string
	Adapter            string
}

// Observer receives execution observations. Implementations must not panic;
// Runtime recovers from observer panics as a final fail-closed safeguard.
type Observer interface {
	Observe(Observation)
}

// ActiveObserver is an optional lifecycle extension for bounded in-flight
// execution gauges. Runtime calls it around Execute; observers that do not
// need a gauge may implement only Observer.
type ActiveObserver interface {
	Begin()
	End()
}

// DurableStoreObserver is an optional extension for durable-store latency and
// failure aggregates. Runtime calls it around execution-status writes;
// observers that do not need storage metrics may implement only Observer.
type DurableStoreObserver interface {
	ObserveDurableStore(duration time.Duration, failed bool)
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
	executedUnconfirmed  int64
	active               int64
	durationCount        int64
	durationBuckets      [8]int64
	durableStoreDuration time.Duration
	durableStoreCalls    int64
	durableStoreErrors   int64
	recoveryDepth        int64
	recoveryOldestAge    time.Duration
	recoveryAttempts     int64
	recoveryRenewals     int64
	recoveryDeadLetters  int64
	byStage              map[string]int64
	byReason             map[string]int64
}

// durationBucketSeconds is fixed to keep telemetry bounded and predictable.
var durationBucketSeconds = [...]float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}

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
	m.durationCount++
	seconds := o.Duration.Seconds()
	for index, boundary := range durationBucketSeconds {
		if seconds <= boundary {
			m.durationBuckets[index]++
		}
	}
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
	if o.Outcome == core.OutcomeExecutedUnconfirmed {
		m.executedUnconfirmed++
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
func (m *Metrics) Begin() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.active++
	m.mu.Unlock()
}

func (m *Metrics) End() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.active > 0 {
		m.active--
	}
	m.mu.Unlock()
}

// ObserveDurableStore records bounded storage latency and failure state. It
// accepts only aggregate values; callers must not turn IDs or SQL into labels.
func (m *Metrics) ObserveDurableStore(duration time.Duration, failed bool) {
	if m == nil {
		return
	}
	if duration < 0 {
		duration = 0
	}
	m.mu.Lock()
	m.durableStoreDuration += duration
	m.durableStoreCalls++
	if failed {
		m.durableStoreErrors++
	}
	m.mu.Unlock()
}

// ObserveRecoveryQueue records queue gauges sampled from the durable store.
// Gauges and counters are split across two methods because a caller that
// knows only one of them would otherwise have to pass zero for the other and
// silently reset it.
func (m *Metrics) ObserveRecoveryQueue(depth int64, oldestAge time.Duration) {
	if m == nil {
		return
	}
	if depth < 0 {
		depth = 0
	}
	if oldestAge < 0 {
		oldestAge = 0
	}
	m.mu.Lock()
	m.recoveryDepth = depth
	m.recoveryOldestAge = oldestAge
	m.mu.Unlock()
}

// ObserveRecoveryProgress records work a recovery worker completed. Values are
// aggregate counters, never labels.
func (m *Metrics) ObserveRecoveryProgress(attempts, renewals, deadLetters int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.recoveryAttempts += maxNonNegative(attempts)
	m.recoveryRenewals += maxNonNegative(renewals)
	m.recoveryDeadLetters += maxNonNegative(deadLetters)
	m.mu.Unlock()
}

func maxNonNegative(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func (m *Metrics) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{
		"total":                          m.total,
		"allowed":                        m.allowed,
		"denied":                         m.denied,
		"duration_seconds":               m.duration.Seconds(),
		"idempotent_replays":             m.replays,
		"approval_required":              m.approvalRequired,
		"quota_rejected":                 m.quotaRejected,
		"idempotency_conflicts":          m.idempotencyConflicts,
		"executed_unconfirmed":           m.executedUnconfirmed,
		"active_executions":              m.active,
		"duration_count":                 m.durationCount,
		"duration_buckets":               append([]int64(nil), m.durationBuckets[:]...),
		"durable_store_duration_seconds": m.durableStoreDuration.Seconds(),
		"durable_store_calls":            m.durableStoreCalls,
		"durable_store_errors":           m.durableStoreErrors,
		"recovery_depth":                 m.recoveryDepth,
		"recovery_oldest_age_seconds":    m.recoveryOldestAge.Seconds(),
		"recovery_attempts":              m.recoveryAttempts,
		"recovery_renewals":              m.recoveryRenewals,
		"recovery_dead_letters":          m.recoveryDeadLetters,
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
	b.WriteString("# HELP loom_active_executions In-flight governed executions.\n")
	b.WriteString("# TYPE loom_active_executions gauge\n")
	fmt.Fprintf(&b, "loom_active_executions %d\n", m.active)
	b.WriteString("# HELP loom_execute_allowed_total Governed executions that completed successfully.\n")
	b.WriteString("# TYPE loom_execute_allowed_total counter\n")
	fmt.Fprintf(&b, "loom_execute_allowed_total %d\n", m.allowed)
	b.WriteString("# HELP loom_execute_denied_total Governed executions denied by the pipeline.\n")
	b.WriteString("# TYPE loom_execute_denied_total counter\n")
	fmt.Fprintf(&b, "loom_execute_denied_total %d\n", m.denied)
	// Deprecated: superseded by loom_execute_duration_seconds_sum, which
	// carries the same value. Retained so existing scrapers keep working.
	b.WriteString("# HELP loom_execute_duration_seconds_total Cumulative execution duration.\n")
	b.WriteString("# TYPE loom_execute_duration_seconds_total counter\n")
	fmt.Fprintf(&b, "loom_execute_duration_seconds_total %f\n", m.duration.Seconds())
	// _sum and _count complete the histogram family; a histogram without _sum
	// cannot answer rate(_sum)/rate(_count) for average latency.
	b.WriteString("# HELP loom_execute_duration_seconds Governed execution duration.\n")
	b.WriteString("# TYPE loom_execute_duration_seconds histogram\n")
	for index, boundary := range durationBucketSeconds {
		fmt.Fprintf(&b, "loom_execute_duration_seconds_bucket{le=\"%g\"} %d\n", boundary, m.durationBuckets[index])
	}
	fmt.Fprintf(&b, "loom_execute_duration_seconds_bucket{le=\"+Inf\"} %d\n", m.durationCount)
	fmt.Fprintf(&b, "loom_execute_duration_seconds_sum %f\n", m.duration.Seconds())
	fmt.Fprintf(&b, "loom_execute_duration_seconds_count %d\n", m.durationCount)
	b.WriteString("# HELP loom_durable_store_duration_seconds_total Cumulative durable-store latency.\n")
	b.WriteString("# TYPE loom_durable_store_duration_seconds_total counter\n")
	fmt.Fprintf(&b, "loom_durable_store_duration_seconds_total %f\n", m.durableStoreDuration.Seconds())
	b.WriteString("# HELP loom_durable_store_calls_total Durable-store calls.\n")
	b.WriteString("# TYPE loom_durable_store_calls_total counter\n")
	fmt.Fprintf(&b, "loom_durable_store_calls_total %d\n", m.durableStoreCalls)
	b.WriteString("# HELP loom_durable_store_errors_total Durable-store failures.\n")
	b.WriteString("# TYPE loom_durable_store_errors_total counter\n")
	fmt.Fprintf(&b, "loom_durable_store_errors_total %d\n", m.durableStoreErrors)
	b.WriteString("# HELP loom_recovery_depth Current recovery queue depth.\n")
	b.WriteString("# TYPE loom_recovery_depth gauge\n")
	fmt.Fprintf(&b, "loom_recovery_depth %d\n", m.recoveryDepth)
	b.WriteString("# HELP loom_recovery_oldest_age_seconds Age of oldest recovery item.\n")
	b.WriteString("# TYPE loom_recovery_oldest_age_seconds gauge\n")
	fmt.Fprintf(&b, "loom_recovery_oldest_age_seconds %f\n", m.recoveryOldestAge.Seconds())
	b.WriteString("# HELP loom_recovery_attempts_total Recovery attempts.\n")
	b.WriteString("# TYPE loom_recovery_attempts_total counter\n")
	fmt.Fprintf(&b, "loom_recovery_attempts_total %d\n", m.recoveryAttempts)
	b.WriteString("# HELP loom_recovery_renewals_total Recovery lease renewals.\n")
	b.WriteString("# TYPE loom_recovery_renewals_total counter\n")
	fmt.Fprintf(&b, "loom_recovery_renewals_total %d\n", m.recoveryRenewals)
	b.WriteString("# HELP loom_recovery_dead_letters_total Recovery items dead-lettered.\n")
	b.WriteString("# TYPE loom_recovery_dead_letters_total counter\n")
	fmt.Fprintf(&b, "loom_recovery_dead_letters_total %d\n", m.recoveryDeadLetters)
	fmt.Fprintf(&b, "loom_execute_idempotent_replays_total %d\n", m.replays)
	fmt.Fprintf(&b, "loom_execute_approval_required_total %d\n", m.approvalRequired)
	fmt.Fprintf(&b, "loom_execute_quota_rejected_total %d\n", m.quotaRejected)
	fmt.Fprintf(&b, "loom_execute_idempotency_conflicts_total %d\n", m.idempotencyConflicts)
	fmt.Fprintf(&b, "loom_execute_executed_unconfirmed_total %d\n", m.executedUnconfirmed)

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
