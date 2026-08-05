package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/boundary"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/quotas"
	"github.com/loreste/loom/resource"
	"github.com/loreste/loom/risk"
	"github.com/loreste/loom/runtime"
)

func TestProductionModeRejectsImplicitStateStores(t *testing.T) {
	_, err := runtime.New(runtime.Dependencies{
		Mode:      runtime.ModeProduction,
		Registry:  core.NewRegistry(),
		Verifier:  identity.NewMemoryVerifier(),
		Boundary:  boundary.NewMemoryChecker(),
		Policy:    policy.NewMemoryEngine(),
		Resources: resource.NewMemoryChecker(),
	})
	if err == nil {
		t.Fatal("production runtime must reject implicit in-memory security stores")
	}
}

// stackWith rebuilds a Runtime over an existing TestStack with selected
// dependencies swapped out (fault injection).
func stackWith(t *testing.T, s *runtime.TestStack, mutate func(d *runtime.Dependencies)) *runtime.Runtime {
	t.Helper()
	d := runtime.Dependencies{
		Registry:    s.Registry,
		Verifier:    s.Verifier,
		Delegation:  s.Delegation,
		Boundary:    s.Boundary,
		Policy:      s.Policy,
		Resources:   s.Resources,
		Fields:      s.Fields,
		Guardrails:  s.Guardrails,
		Risk:        risk.NewSimpleEngine(),
		RiskBlock:   s.RiskBlock,
		Approval:    s.Approval,
		Quotas:      s.Quotas,
		Idempotency: s.Idempotency,
		Audit:       audit.NewLogger(s.AuditSink),
	}
	if mutate != nil {
		mutate(&d)
	}
	rt, err := runtime.New(d)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func paymentReq(token, idemKey string) core.Request {
	return core.Request{
		Operation:      "payment.capture",
		Credentials:    core.Credentials{Scheme: "bearer", Token: "tok-alice"},
		Boundary:       "dev",
		Resource:       &core.ResourceRef{Type: "payment", ID: "pay-1"},
		Input:          map[string]any{"amount": 50.0},
		IdempotencyKey: idemKey,
		ApprovalToken:  token,
	}
}

// A single-use approval token must NOT be burned when a later gate (quota)
// denies the request: the same token must still work once quota allows.
func TestApprovalTokenNotBurnedByQuotaDeny(t *testing.T) {
	s := setupGranted(t)
	if err := s.Quotas.SetLimit("user:alice", "dev", "payment.capture", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	_ = s.Approval.Issue("tok-q1", "user:alice", "payment.capture", "dev", core.RiskCritical, time.Hour)
	resp := s.Runtime.Execute(context.Background(), paymentReq("tok-q1", "idem-q1"))
	if !resp.Allowed {
		t.Fatalf("first call: %+v", resp.Denial)
	}

	// Quota now exhausted; approval passes but quota denies.
	_ = s.Approval.Issue("tok-q2", "user:alice", "payment.capture", "dev", core.RiskCritical, time.Hour)
	resp = s.Runtime.Execute(context.Background(), paymentReq("tok-q2", "idem-q2"))
	if resp.Allowed || resp.Denial.Reason != core.ReasonQuotaExceeded {
		t.Fatalf("expected quota deny, got %+v", resp.Denial)
	}

	// Raise the limit; the same token must still be valid (not burned).
	if err := s.Quotas.SetLimit("user:alice", "dev", "payment.capture", 10, time.Minute); err != nil {
		t.Fatal(err)
	}
	resp = s.Runtime.Execute(context.Background(), paymentReq("tok-q2", "idem-q2"))
	if !resp.Allowed {
		t.Fatalf("token must not be burned by quota deny: %+v", resp.Denial)
	}
}

// Handler failure still burns the approval token (claimed before exec to prevent
// dual money side-effects). Quota is refunded so a new approval can proceed.
func TestApprovalBurnedOnHandlerFailureButQuotaRefunded(t *testing.T) {
	s := setupGranted(t)
	if err := s.Quotas.SetLimit("user:alice", "dev", "payment.failable", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	_ = s.Policy.AddRule(policy.Rule{Principal: "user:alice", Boundary: "dev", Operation: "payment.failable", Priority: 1})
	s.Registry.MustRegister(&core.Operation{
		Name:        "payment.failable",
		Permissions: []string{"payment.capture"},
		Risk:        core.RiskHigh,
		Quota:       core.QuotaPolicy{RefundOnHandlerError: true},
		Approval:    core.ApprovalPolicy{Required: true},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		if ec.Input["fail"] == true {
			return nil, errors.New("capture failed")
		}
		return &core.Result{Output: map[string]any{"status": "captured"}}, nil
	})

	req := core.Request{
		Operation:   "payment.failable",
		Credentials: core.Credentials{Scheme: "bearer", Token: "tok-alice"},
		Boundary:    "dev",
		Input:       map[string]any{"fail": true},
	}
	_ = s.Approval.Issue("tok-f1", "user:alice", "payment.failable", "dev", core.RiskCritical, time.Hour)
	req.ApprovalToken = "tok-f1"
	resp := s.Runtime.Execute(context.Background(), req)
	if resp.Allowed || resp.Denial.Reason != core.ReasonExecutionFailed {
		t.Fatalf("expected execution failure, got %+v", resp.Denial)
	}

	// Same token is burned (fail closed). Fresh approval + quota refund works.
	req.Input = map[string]any{"fail": false}
	resp = s.Runtime.Execute(context.Background(), req)
	if resp.Allowed {
		t.Fatal("burned token must not reuse")
	}
	_ = s.Approval.Issue("tok-f2", "user:alice", "payment.failable", "dev", core.RiskCritical, time.Hour)
	req.ApprovalToken = "tok-f2"
	resp = s.Runtime.Execute(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("new token after quota refund must succeed: %+v", resp.Denial)
	}
}

// A token issued for boundary "dev" must be rejected in "prod".
func TestApprovalBoundaryMismatchRejected(t *testing.T) {
	s := setupGranted(t)
	// user:carol has NO pinned home boundary and membership in both dev and
	// prod, so the ONLY thing that can deny her prod call is the approval
	// boundary binding.
	if err := s.Verifier.Register(identity.StaticPrincipal{
		ID:           "user:carol",
		Type:         "user",
		Token:        "tok-carol",
		Capabilities: []string{"payment.capture"},
	}); err != nil {
		t.Fatal(err)
	}
	for _, b := range []core.BoundaryID{"dev", "prod"} {
		if err := s.Boundary.Grant("user:carol", b); err != nil {
			t.Fatal(err)
		}
		_ = s.Policy.AddRule(policy.Rule{Principal: "user:carol", Boundary: b, Operation: "payment.capture", Priority: 1})
		_ = s.Resources.Grant(resource.Rule{Principal: "user:carol", Boundary: b, Type: "payment", ID: "*", Operations: []string{"payment.capture"}})
		_ = s.Fields.GrantFields("user:carol", b, "payment.capture", []string{"*"})
	}

	req := paymentReq("tok-dev-only", "idem-b1")
	req.Credentials.Token = "tok-carol"
	req.Boundary = "prod"
	_ = s.Approval.Issue("tok-dev-only", "user:carol", "payment.capture", "dev", core.RiskCritical, time.Hour)
	resp := s.Runtime.Execute(context.Background(), req)
	if resp.Allowed || resp.Denial.Reason != core.ReasonApprovalRequired {
		t.Fatalf("dev token in prod must be denied, got %+v", resp.Denial)
	}

	// A prod-scoped token works in prod.
	_ = s.Approval.Issue("tok-prod", "user:carol", "payment.capture", "prod", core.RiskCritical, time.Hour)
	req.ApprovalToken = "tok-prod"
	resp = s.Runtime.Execute(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("prod token in prod must succeed: %+v", resp.Denial)
	}
}

// consumeFailEngine approves at Evaluate but always fails Consume.
type consumeFailEngine struct{ inner approval.Engine }

func (e consumeFailEngine) Evaluate(ctx context.Context, id core.Identity, op *core.Operation, risk core.RiskLevel, boundary core.BoundaryID, token string) approval.Decision {
	return e.inner.Evaluate(ctx, id, op, risk, boundary, token)
}

func (e consumeFailEngine) Consume(context.Context, core.Identity, *core.Operation, core.BoundaryID, string) error {
	return errors.New("consume store exploded")
}

// If Consume fails before the handler, the runtime must deny without running
// the handler, and the token must remain unconsumed for a healthy retry.
func TestApprovalConsumeFailureFailsClosed(t *testing.T) {
	s := setupGranted(t)
	// Ensure payment handler is still registered; we only swap approval engine.
	rt := stackWith(t, s, func(d *runtime.Dependencies) {
		d.Approval = consumeFailEngine{inner: s.Approval}
	})
	_ = s.Approval.Issue("tok-cf", "user:alice", "payment.capture", "dev", core.RiskCritical, time.Hour)
	resp := rt.Execute(context.Background(), paymentReq("tok-cf", "idem-cf"))
	if resp.Allowed {
		t.Fatal("consume failure before handler must deny")
	}
	if resp.Denial == nil || resp.Denial.Reason != core.ReasonApprovalDenied {
		t.Fatalf("expected approval_denied, got %+v", resp.Denial)
	}
	if resp.Output != nil {
		t.Fatalf("output must not be returned on consume failure: %v", resp.Output)
	}

	// Token was not burned: a healthy runtime accepts it.
	resp = s.Runtime.Execute(context.Background(), paymentReq("tok-cf", "idem-cf2"))
	if !resp.Allowed {
		t.Fatalf("token must remain unconsumed after consume failure: %+v", resp.Denial)
	}
}

// Concurrent Executes with the same approval token: exactly one allow.
func TestApprovalConcurrentConsumeAtMostOneHandler(t *testing.T) {
	s := setupGranted(t)
	_ = s.Approval.Issue("tok-race", "user:alice", "payment.capture", "dev", core.RiskCritical, time.Hour)

	const n = 8
	var wg sync.WaitGroup
	var allowed atomic.Int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			req := paymentReq("tok-race", fmt.Sprintf("idem-race-%d", i))
			resp := s.Runtime.Execute(context.Background(), req)
			if resp.Allowed {
				allowed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if allowed.Load() != 1 {
		t.Fatalf("exactly one allow expected, got %d", allowed.Load())
	}
}

// toggleSink fails audit writes when fail is set.
type toggleSink struct {
	mu    sync.Mutex
	fail  bool
	inner *audit.MemorySink
}

func (s *toggleSink) Write(ctx context.Context, ev audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("audit sink down")
	}
	return s.inner.Write(ctx, ev)
}

func (s *toggleSink) setFail(f bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = f
}

// An audit emit failure on the allow path must convert the response into a
// deny with no output. The idempotency key is intentionally NOT aborted after
// a successful handler (prevents a second side-effect).
func TestAuditFailureOnAllowFailsClosed(t *testing.T) {
	s := setupGranted(t)
	sink := &toggleSink{inner: &audit.MemorySink{}}
	rt := stackWith(t, s, func(d *runtime.Dependencies) {
		d.Audit = audit.NewLogger(sink)
	})

	sink.setFail(true)
	req := baseReq()
	req.IdempotencyKey = "idem-audit-1"
	resp := rt.Execute(context.Background(), req)
	if resp.Allowed {
		t.Fatal("audit failure on allow path must deny")
	}
	if resp.Denial == nil || resp.Denial.Reason != core.ReasonExecutedUnconfirmed {
		t.Fatalf("expected executed-unconfirmed reason, got %+v", resp.Denial)
	}
	if resp.Outcome != core.OutcomeExecutedUnconfirmed || resp.ExecutionID == "" {
		t.Fatalf("expected explicit indeterminate outcome and execution id, got %+v", resp)
	}
	if resp.Output != nil {
		t.Fatalf("output must not be returned when audit fails: %v", resp.Output)
	}

	// Same key remains in-flight / held — must not re-execute the handler.
	sink.setFail(false)
	resp = rt.Execute(context.Background(), req)
	if resp.Allowed {
		t.Fatal("same idempotency key must not re-execute after post-handler audit failure")
	}

	// A new key with healthy audit succeeds.
	req.IdempotencyKey = "idem-audit-2"
	resp = rt.Execute(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("fresh key must succeed: %+v", resp.Denial)
	}
}

func TestOutputSchemaFailureReturnsNoData(t *testing.T) {
	s := setupGranted(t)
	if err := s.Policy.AddRule(policy.Rule{Principal: "user:alice", Boundary: "dev", Operation: "contract.read", Priority: 10}); err != nil {
		t.Fatal(err)
	}
	if err := s.Fields.GrantFields("user:alice", "dev", "contract.read", []string{"id", "unexpected"}); err != nil {
		t.Fatal(err)
	}
	s.Registry.MustRegister(&core.Operation{
		Name:         "contract.read",
		InputSchema:  []byte(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}`),
		OutputSchema: []byte(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}`),
		Effects:      []core.Effect{core.EffectRead},
	}, func(*core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{"id": "ok", "unexpected": "must not escape"}}, nil
	})
	resp := s.Runtime.Execute(context.Background(), core.Request{
		Operation:   "contract.read",
		Credentials: core.Credentials{Scheme: "bearer", Token: "tok-alice"},
		Boundary:    "dev",
		Input:       map[string]any{"id": "x"},
	})
	if resp.Allowed || resp.Output != nil || resp.Denial == nil || resp.Denial.Reason != core.ReasonOutputFilter {
		t.Fatalf("invalid output must deny without data: %+v", resp)
	}
}

// An audit emit failure on the replay path must also fail closed.
func TestAuditFailureOnReplayFailsClosed(t *testing.T) {
	s := setupGranted(t)
	sink := &toggleSink{inner: &audit.MemorySink{}}
	rt := stackWith(t, s, func(d *runtime.Dependencies) {
		d.Audit = audit.NewLogger(sink)
	})

	req := baseReq()
	req.IdempotencyKey = "idem-audit-2"
	resp := rt.Execute(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("first call: %+v", resp.Denial)
	}

	sink.setFail(true)
	resp = rt.Execute(context.Background(), req)
	if resp.Allowed || resp.IdempotentReplay {
		t.Fatalf("replay with failing audit must deny, got %+v", resp)
	}

	sink.setFail(false)
	resp = rt.Execute(context.Background(), req)
	if !resp.Allowed || !resp.IdempotentReplay {
		t.Fatalf("replay must succeed once audit healthy: %+v", resp)
	}
}

// An audit emit failure on the deny path must not change the decision.
func TestAuditFailureOnDenyStillDenies(t *testing.T) {
	s := setupGranted(t)
	sink := &toggleSink{inner: &audit.MemorySink{}, fail: true}
	rt := stackWith(t, s, func(d *runtime.Dependencies) {
		d.Audit = audit.NewLogger(sink)
	})
	req := baseReq()
	req.Credentials.Token = "wrong"
	resp := rt.Execute(context.Background(), req)
	if resp.Allowed {
		t.Fatal("deny must stand even when audit emit fails")
	}
	if resp.Denial == nil || resp.Denial.Reason != core.ReasonUnauthenticated {
		t.Fatalf("expected unauthenticated, got %+v", resp.Denial)
	}
}

// A replay audit event must link back to the original execution's audit ID.
func TestReplayLinksPriorAuditID(t *testing.T) {
	s := setupGranted(t)
	req := baseReq()
	req.IdempotencyKey = "idem-link"
	resp := s.Runtime.Execute(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("first call: %+v", resp.Denial)
	}
	resp2 := s.Runtime.Execute(context.Background(), req)
	if !resp2.Allowed || !resp2.IdempotentReplay {
		t.Fatalf("expected replay: %+v", resp2)
	}
	var found bool
	for _, ev := range s.AuditSink.Snapshot() {
		if ev.ID == resp2.AuditID {
			found = true
			if ev.PriorAuditID != resp.AuditID {
				t.Fatalf("replay audit must link prior id %q, got %q", resp.AuditID, ev.PriorAuditID)
			}
		}
	}
	if !found {
		t.Fatal("replay audit event not found")
	}
}

// An already-canceled context must be denied at entry.
func TestContextCanceledAtEntry(t *testing.T) {
	s := setupGranted(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp := s.Runtime.Execute(ctx, baseReq())
	if resp.Allowed || resp.Denial.Reason != core.ReasonContextCanceled {
		t.Fatalf("canceled ctx must deny with context_canceled, got %+v", resp.Denial)
	}
}

// A past-deadline context must be denied at entry.
func TestContextDeadlineExceededAtEntry(t *testing.T) {
	s := setupGranted(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	resp := s.Runtime.Execute(ctx, baseReq())
	if resp.Allowed || resp.Denial.Reason != core.ReasonContextCanceled {
		t.Fatalf("expired ctx must deny with context_canceled, got %+v", resp.Denial)
	}
}

// cancelLimiter cancels the request context inside the quota gate, simulating
// a client disconnect after the last ctx-aware gate but before the handler.
type cancelLimiter struct {
	inner  quotas.Limiter
	cancel context.CancelFunc
}

func (l cancelLimiter) Allow(ctx context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error {
	err := l.inner.Allow(ctx, id, boundary, op, n)
	l.cancel()
	return err
}

func (l cancelLimiter) Refund(ctx context.Context, id core.Identity, boundary core.BoundaryID, op string, n int64) error {
	return l.inner.Refund(ctx, id, boundary, op, n)
}

// A context canceled while gates run must be denied before the handler runs.
func TestContextCanceledBeforeHandler(t *testing.T) {
	s := setupGranted(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := stackWith(t, s, func(d *runtime.Dependencies) {
		d.Quotas = cancelLimiter{inner: s.Quotas, cancel: cancel}
	})

	handlerRan := false
	s.Registry.MustRegister(&core.Operation{
		Name:        "document.cancelcheck",
		Permissions: []string{"document.read"},
		Risk:        core.RiskLow,
		Effects:     []core.Effect{core.EffectRead},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		handlerRan = true
		return &core.Result{Output: map[string]any{"ok": true}}, nil
	})
	_ = s.Policy.AddRule(policy.Rule{Principal: "user:alice", Boundary: "dev", Operation: "document.cancelcheck", Priority: 1})

	req := baseReq()
	req.Operation = "document.cancelcheck"
	req.Resource = nil // op declares no resources
	resp := rt.Execute(ctx, req)
	if resp.Allowed || resp.Denial.Reason != core.ReasonContextCanceled {
		t.Fatalf("expected context_canceled, got %+v", resp.Denial)
	}
	if handlerRan {
		t.Fatal("handler must not run on canceled context")
	}
}

// Mutating the *Operation returned by Registry.Get must not affect enforcement.
func TestRegistryGetMutationDoesNotAffectExecute(t *testing.T) {
	s := setupGranted(t)
	op, err := s.Registry.Get("document.read")
	if err != nil {
		t.Fatal(err)
	}
	// Escalate what a leaked pointer could do: require root permission,
	// critical risk, and mandatory approval.
	op.Permissions[0] = "root.only"
	op.Risk = core.RiskCritical
	op.Approval.Required = true
	op.SensitiveFields = append(op.SensitiveFields, "id")

	resp := s.Runtime.Execute(context.Background(), baseReq())
	if !resp.Allowed {
		t.Fatalf("mutation of returned op must not affect enforcement: %+v", resp.Denial)
	}
	if _, ok := resp.Output["id"]; !ok {
		t.Fatal("sensitive-field mutation leaked into enforcement")
	}
}

// A panicking custom Clock must not escape Execute.
func TestPanickingClockDoesNotEscape(t *testing.T) {
	s := setupGranted(t)
	rt := stackWith(t, s, func(d *runtime.Dependencies) {
		d.Clock = func() time.Time { panic("clock exploded") }
	})
	resp := rt.Execute(context.Background(), baseReq()) // must not panic
	if resp.Allowed {
		t.Fatal("panicking clock must yield deny")
	}
	if resp.Denial == nil || resp.Denial.Reason != core.ReasonInternal {
		t.Fatalf("expected internal deny, got %+v", resp.Denial)
	}
}

// panicSink panics on every Write.
type panicSink struct{}

func (panicSink) Write(context.Context, audit.Event) error { panic("sink exploded") }

// A panicking audit sink on the deny path must not escape Execute: the
// recovery path itself recovers and falls back to a static deny.
func TestPanickingAuditSinkOnDenyDoesNotEscape(t *testing.T) {
	s := setupGranted(t)
	rt := stackWith(t, s, func(d *runtime.Dependencies) {
		d.Audit = audit.NewLogger(panicSink{})
	})
	req := baseReq()
	req.Credentials.Token = "wrong"
	resp := rt.Execute(context.Background(), req) // must not panic
	if resp.Allowed {
		t.Fatal("must deny")
	}
	if resp.Denial == nil {
		t.Fatal("expected a denial struct even with panicking sink")
	}
}

// Mutating the returned Output map must not corrupt the stored replay.
func TestIdempotentReplayOutputNotAliased(t *testing.T) {
	s := setupGranted(t)
	req := baseReq()
	req.IdempotencyKey = "idem-alias"
	resp := s.Runtime.Execute(context.Background(), req)
	if !resp.Allowed {
		t.Fatalf("first call: %+v", resp.Denial)
	}
	// Corrupt the caller-visible output after the fact.
	resp.Output["id"] = "hacked"
	resp.Output["injected"] = true

	resp2 := s.Runtime.Execute(context.Background(), req)
	if !resp2.Allowed || !resp2.IdempotentReplay {
		t.Fatalf("expected replay: %+v", resp2)
	}
	if resp2.Output["id"] != "doc-1" {
		t.Fatalf("stored replay corrupted by caller mutation: %v", resp2.Output["id"])
	}
	if _, ok := resp2.Output["injected"]; ok {
		t.Fatal("caller-injected field appeared in stored replay")
	}
}
