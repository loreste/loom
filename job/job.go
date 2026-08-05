// Package job provides a minimal job queue that processes work through Loom.
// Jobs are not a privilege path: each job becomes app.Call / Runtime.Execute.
package job

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// Job is one unit of work mapped to a Loom operation.
type Job struct {
	// ID unique job id (used as default idempotency key).
	ID string
	// Operation Loom operation name.
	Operation string
	// Boundary isolation.
	Boundary core.BoundaryID
	// Input operation payload.
	Input map[string]any
	// Resource optional.
	Resource *core.ResourceRef
	// IdempotencyKey overrides ID when set.
	IdempotencyKey string
	// ApprovalToken optional.
	ApprovalToken string
	// Token bearer for the worker identity (or set Runner.Token).
	Token string
	// Metadata optional adapter baggage.
	Metadata map[string]string
}

// Result of processing one job.
type Result struct {
	JobID    string
	Response core.Response
	Err      error
	Duration time.Duration
}

// Queue is a job source. Implementations must be safe for concurrent Poll.
type Queue interface {
	// Enqueue adds a job.
	Enqueue(ctx context.Context, j Job) error
	// Poll returns the next job or (zero, false, nil) when empty.
	// Blocking optional: return quickly if none.
	Poll(ctx context.Context) (Job, bool, error)
}

// Caller is satisfied by app.App and similar.
type Caller interface {
	Call(ctx context.Context, req core.Request) core.Response
}

// MemoryQueue is an in-process FIFO queue.
type MemoryQueue struct {
	mu   sync.Mutex
	jobs []Job
}

// NewMemoryQueue creates an empty queue.
func NewMemoryQueue() *MemoryQueue {
	return &MemoryQueue{}
}

// Enqueue implements Queue.
func (q *MemoryQueue) Enqueue(_ context.Context, j Job) error {
	if q == nil {
		return fmt.Errorf("%w: nil queue", core.ErrInvalidArgument)
	}
	if j.ID == "" || j.Operation == "" {
		return fmt.Errorf("%w: job id and operation required", core.ErrInvalidArgument)
	}
	q.mu.Lock()
	q.jobs = append(q.jobs, j)
	q.mu.Unlock()
	return nil
}

// Poll implements Queue.
func (q *MemoryQueue) Poll(_ context.Context) (Job, bool, error) {
	if q == nil {
		return Job{}, false, fmt.Errorf("%w: nil queue", core.ErrInvalidArgument)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) == 0 {
		return Job{}, false, nil
	}
	j := q.jobs[0]
	q.jobs = q.jobs[1:]
	return j, true, nil
}

// Len returns pending jobs.
func (q *MemoryQueue) Len() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}

// Runner polls a queue and executes each job through Caller (Loom).
type Runner struct {
	Queue  Queue
	Caller Caller
	// Token default bearer for jobs without Token.
	Token string
	// PollInterval when queue empty (default 200ms).
	PollInterval time.Duration
	// OnResult optional callback after each job.
	OnResult func(Result)
	// StopOnDeny stops the runner when a job is denied (default false).
	StopOnDeny bool
}

// Run processes jobs until ctx cancelled. Empty queue spins on PollInterval.
func (r *Runner) Run(ctx context.Context) error {
	if r == nil || r.Queue == nil || r.Caller == nil {
		return fmt.Errorf("%w: runner not configured", core.ErrInvalidArgument)
	}
	interval := r.PollInterval
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		j, ok, err := r.Queue.Poll(ctx)
		if err != nil {
			return err
		}
		if !ok {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
				continue
			}
		}
		res := r.process(ctx, j)
		if r.OnResult != nil {
			r.OnResult(res)
		}
		if r.StopOnDeny && res.Err == nil && !res.Response.Allowed {
			return fmt.Errorf("job %s denied: %v", j.ID, res.Response.Denial)
		}
	}
}

// ProcessOne polls at most one job (for tests).
func (r *Runner) ProcessOne(ctx context.Context) (Result, bool, error) {
	if r == nil || r.Queue == nil || r.Caller == nil {
		return Result{}, false, fmt.Errorf("%w: runner not configured", core.ErrInvalidArgument)
	}
	j, ok, err := r.Queue.Poll(ctx)
	if err != nil || !ok {
		return Result{}, ok, err
	}
	return r.process(ctx, j), true, nil
}

func (r *Runner) process(ctx context.Context, j Job) Result {
	start := time.Now()
	token := j.Token
	if token == "" {
		token = r.Token
	}
	idem := j.IdempotencyKey
	if idem == "" {
		idem = j.ID
	}
	md := map[string]string{"adapter": "job", "job_id": j.ID}
	for k, v := range j.Metadata {
		// Never let adapter baggage override runner-owned audit metadata.
		if k == "adapter" || k == "job_id" {
			continue
		}
		md[k] = v
	}
	resp := r.Caller.Call(ctx, core.Request{
		Operation:      j.Operation,
		Credentials:    core.Credentials{Scheme: "bearer", Token: token},
		Boundary:       j.Boundary,
		Resource:       j.Resource,
		Input:          j.Input,
		IdempotencyKey: idem,
		ApprovalToken:  j.ApprovalToken,
		Metadata:       md,
	})
	res := Result{
		JobID:    j.ID,
		Response: resp,
		Duration: time.Since(start),
	}
	// Populate Err for non-policy failures (internal/transport-class denials)
	// so StopOnDeny and OnResult can distinguish them from real denials.
	if !resp.Allowed && resp.Denial != nil && isInfraReason(resp.Denial.Reason) {
		res.Err = fmt.Errorf("job %s failed: %s", j.ID, resp.Denial.Reason)
	}
	return res
}

// isInfraReason reports deny reasons that mean the call never got a policy
// verdict (transport/infra failure), as opposed to an actual denial.
func isInfraReason(reason string) bool {
	switch reason {
	case core.ReasonInternal, core.ReasonExecutionFailed, core.ReasonContextCanceled:
		return true
	default:
		return false
	}
}
