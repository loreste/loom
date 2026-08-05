// Package runtime is the Loom execution-governance pipeline.
//
// Adversarial contract:
//   - Default decision is DENY.
//   - Any step error ⇒ DENY (fail-closed), except successful business handler errors
//     which still audit as execution_failed and do not invent allow.
//   - Adapters cannot skip steps; Execute is the only entrypoint.
//   - Identity is only trusted after Verifier succeeds.
//   - Output is always field-filtered and secret-redacted before return.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/boundary"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/guardrails"
	"github.com/loreste/loom/idempotency"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/quotas"
	"github.com/loreste/loom/resource"
	"github.com/loreste/loom/risk"
)

// Dependencies for the runtime. Missing security deps fail closed at Execute.
// TenantResolver binds a verified identity claim to the requested boundary.
// Implementations must reject missing or conflicting tenant context.
type TenantResolver interface {
	Resolve(context.Context, core.Identity, core.BoundaryID) (core.BoundaryID, error)
}

type Dependencies struct {
	Registry    *core.Registry
	Verifier    identity.Verifier
	Delegation  identity.DelegationValidator // optional; required only if request has delegation
	Boundary    boundary.Checker
	Policy      policy.Engine
	Resources   resource.Checker
	Fields      *resource.FieldFilter
	Guardrails  *guardrails.Chain
	Risk        risk.Engine
	RiskBlock   *risk.Blocker // optional hard risk ceiling
	Approval    approval.Engine
	Quotas      quotas.Limiter
	Idempotency idempotency.Store
	Audit       *audit.Logger
	Observer    Observer

	// AllowAnonymous is false by default. If true, empty credentials get a synthetic
	// unauthenticated identity that still must pass policy (almost always deny).
	AllowAnonymous bool
	// Tenant runs after authentication/delegation and before boundary
	// authorization. Its resolved boundary is used by all later gates.
	Tenant TenantResolver

	// Clock for tests; nil = time.Now.
	Clock func() time.Time
}

// Runtime is the universal enforcement engine.
type Runtime struct {
	deps Dependencies
}

// New constructs a Runtime. Does not invent default allow policies.
func New(deps Dependencies) (*Runtime, error) {
	if deps.Registry == nil {
		return nil, fmt.Errorf("%w: registry required", core.ErrInvalidArgument)
	}
	if deps.Verifier == nil {
		return nil, fmt.Errorf("%w: verifier required", core.ErrInvalidArgument)
	}
	if deps.Boundary == nil {
		return nil, fmt.Errorf("%w: boundary checker required", core.ErrInvalidArgument)
	}
	if deps.Policy == nil {
		return nil, fmt.Errorf("%w: policy engine required", core.ErrInvalidArgument)
	}
	if deps.Resources == nil {
		return nil, fmt.Errorf("%w: resource checker required", core.ErrInvalidArgument)
	}
	if deps.Fields == nil {
		// Fail closed field filter: strip all.
		deps.Fields = resource.NewFieldFilter()
	}
	if deps.Guardrails == nil {
		deps.Guardrails = guardrails.DefaultChain()
	}
	if deps.Risk == nil {
		deps.Risk = risk.NewSimpleEngine()
	}
	if deps.Approval == nil {
		deps.Approval = approval.NewMemoryEngine()
	}
	if deps.Quotas == nil {
		deps.Quotas = quotas.NewMemoryLimiter()
	}
	if deps.Idempotency == nil {
		deps.Idempotency = idempotency.NewMemoryStore()
	}
	if deps.Audit == nil {
		deps.Audit = audit.NewLogger(&audit.MemorySink{})
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	return &Runtime{deps: deps}, nil
}

// Execute runs the full permission pipeline. Never panics out; recovers to deny.
func (rt *Runtime) Execute(ctx context.Context, req core.Request) (resp core.Response) {
	var start time.Time
	defer func() {
		defer func() { _ = recover() }()
		if rt != nil && rt.deps.Observer != nil {
			step, reason := "complete", "allow"
			if resp.Denial != nil {
				step, reason = resp.Denial.Step, resp.Denial.Reason
			}
			duration := time.Duration(0)
			if !start.IsZero() {
				duration = time.Since(start)
			}
			rt.deps.Observer.Observe(Observation{
				Operation:        req.Operation,
				Boundary:         req.Boundary,
				Decision:         resp.Decision,
				Reason:           reason,
				Step:             step,
				Duration:         duration,
				IdempotentReplay: resp.IdempotentReplay,
			})
		}
	}()
	// Register recovery FIRST: a panicking custom Clock (or anything else below)
	// must not escape Execute. panicDeny tolerates a zero start and itself
	// recovers if deny/audit panic during recovery.
	defer func() {
		if rec := recover(); rec != nil {
			resp = rt.panicDeny(ctx, req, rec, start)
		}
	}()
	start = rt.deps.Clock()

	if ctx == nil {
		ctx = context.Background()
	}
	if req.TraceID == "" {
		req.TraceID = core.NewTraceID()
	}
	if !req.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, req.Deadline)
		defer cancel()
	}

	// Fail fast on an already-canceled / past-deadline context instead of
	// running the full pipeline.
	if err := ctx.Err(); err != nil {
		return rt.deny(ctx, req, core.Identity{}, nil, core.RiskLow, "context", core.ReasonContextCanceled, ctxErrMessage(err), start, "")
	}

	// 0. Normalize input map
	if req.Input == nil {
		req.Input = map[string]any{}
	}

	// 1. Authenticate
	id, err := rt.authenticate(ctx, req)
	if err != nil {
		return rt.deny(ctx, req, core.Identity{}, nil, core.RiskLow, "authenticate", core.ReasonUnauthenticated, err.Error(), start, "")
	}

	// 2. Delegation
	if req.Delegation != nil {
		if rt.deps.Delegation == nil {
			return rt.deny(ctx, req, id, nil, core.RiskLow, "delegation", core.ReasonInvalidDelegation, "delegation not configured", start, "")
		}
		delegated, err := rt.deps.Delegation.Validate(ctx, id, req.Delegation)
		if err != nil {
			return rt.deny(ctx, req, id, nil, core.RiskLow, "delegation", core.ReasonInvalidDelegation, err.Error(), start, "")
		}
		id = delegated
	}

	// Tenant claim resolution must happen before boundary authorization so the
	// resolved value is carried through every subsequent gate and audit record.
	if rt.deps.Tenant != nil {
		resolved, err := rt.deps.Tenant.Resolve(ctx, id, req.Boundary)
		if err != nil {
			return rt.deny(ctx, req, id, nil, core.RiskLow, "tenant", core.ReasonBoundaryViolation, err.Error(), start, "")
		}
		req.Boundary = resolved
	}

	// 3. Boundary
	if err := rt.deps.Boundary.Allow(ctx, id, req.Boundary); err != nil {
		return rt.deny(ctx, req, id, nil, core.RiskLow, "boundary", core.ReasonBoundaryViolation, err.Error(), start, "")
	}

	// Resolve operation — unknown ⇒ deny
	op, err := rt.deps.Registry.Get(req.Operation)
	if err != nil {
		return rt.deny(ctx, req, id, nil, core.RiskLow, "operation", core.ReasonOperationUnknown, err.Error(), start, "")
	}

	// 4. Operation permission
	dec := rt.deps.Policy.CheckOperationPermission(ctx, id, op)
	if !dec.Decision.Allowed() {
		reason := dec.Reason
		if reason == "" {
			reason = core.ReasonOperationDenied
		}
		return rt.deny(ctx, req, id, op, core.RiskLow, "operation_permission", reason, dec.Message, start, "")
	}

	// 5. Resource permission
	if err := rt.deps.Resources.Allow(ctx, id, req.Boundary, op, req.Resource); err != nil {
		return rt.deny(ctx, req, id, op, core.RiskLow, "resource", core.ReasonResourceDenied, err.Error(), start, "")
	}

	// 6. Field permission is applied post-exec; pre-check: if Fields requested and filter has no grants at all for "*",
	// we still allow execution but may return empty output — adversarial: better than leaking.
	// (No early deny here to avoid resource existence oracle unless policy wants it.)

	// 7. Contextual policy
	cdec := rt.deps.Policy.EvaluateContextual(ctx, id, req.Boundary, op, &req)
	if !cdec.Decision.Allowed() {
		reason := cdec.Reason
		if reason == "" {
			reason = core.ReasonPolicyDeny
		}
		return rt.deny(ctx, req, id, op, core.RiskLow, "contextual_policy", reason, cdec.Message, start, "")
	}

	// 8. Guardrails
	gr := rt.deps.Guardrails.Check(ctx, id, op, &req)
	if !gr.OK {
		return rt.deny(ctx, req, id, op, core.RiskLow, "guardrails:"+gr.Name, core.ReasonGuardrail, gr.Message, start, "")
	}

	// 9. Risk
	riskLevel := rt.deps.Risk.Evaluate(ctx, id, op, &req)
	if rt.deps.RiskBlock != nil {
		if msg := rt.deps.RiskBlock.Check(id, riskLevel); msg != "" {
			return rt.deny(ctx, req, id, op, riskLevel, "risk", core.ReasonRiskBlocked, msg, start, "")
		}
	}

	// 10. Idempotency lookup BEFORE approval/quota consumption.
	// Authorized callers with the same key+fingerprint get a replay without
	// re-consuming single-use approval tokens or quota. Authn/authz already ran.
	var (
		idemKey   string
		idemFP    string
		idemBegin bool
	)
	if op.Idempotency.Required && req.IdempotencyKey == "" {
		return rt.deny(ctx, req, id, op, riskLevel, "idempotency", core.ReasonSchemaInvalid, "idempotency key required", start, "")
	}
	if req.IdempotencyKey != "" {
		fp, err := idempotency.Fingerprint(&req)
		if err != nil {
			return rt.deny(ctx, req, id, op, riskLevel, "idempotency", core.ReasonInternal, err.Error(), start, "")
		}
		idemFP = fp
		idemKey = idempotency.CompositeKey(id.ID, req.Boundary, op.Name, req.IdempotencyKey)
		if stored, ok, err := rt.deps.Idempotency.Get(ctx, idemKey); err != nil {
			return rt.deny(ctx, req, id, op, riskLevel, "idempotency", core.ReasonInternal, err.Error(), start, "")
		} else if ok {
			if stored.Fingerprint != idemFP {
				return rt.deny(ctx, req, id, op, riskLevel, "idempotency", core.ReasonIdempotencyConflict, "idempotency key reuse with different payload", start, "")
			}
			replay := stored.Response
			replay.IdempotentReplay = true
			replay.TraceID = req.TraceID
			// Fail closed: an audit emit error converts the replay into a deny.
			auditID, aerr := rt.audit(ctx, req, id, op, riskLevel, core.DecisionAllow, "idempotency", "allow", "idempotent replay", start, replay.AuditID)
			if aerr != nil {
				log.Printf("loom: audit emit failed on replay path (failing closed): %v", aerr)
				return rt.deny(ctx, req, id, op, riskLevel, "audit", core.ReasonInternal, "audit emit failed: "+aerr.Error(), start, "")
			}
			replay.AuditID = auditID
			return replay
		}
	}

	// 11. Approval check (only for new executions; replays returned above).
	// Evaluate validates the token without burning. Atomic Consume happens
	// immediately before the handler so concurrent callers cannot double-exec
	// money/write ops, while quota/idempotency denials still leave the token usable.
	apr := rt.deps.Approval.Evaluate(ctx, id, op, riskLevel, req.Boundary, req.ApprovalToken)
	if apr.Required && !apr.Approved {
		return rt.deny(ctx, req, id, op, riskLevel, "approval", core.ReasonApprovalRequired, apr.Message, start, "")
	}

	// 12. Quotas (replays do not consume)
	quotaCharged := false
	if err := rt.deps.Quotas.Allow(ctx, id, req.Boundary, op.Name, 1); err != nil {
		return rt.deny(ctx, req, id, op, riskLevel, "quotas", core.ReasonQuotaExceeded, err.Error(), start, "")
	}
	quotaCharged = true

	// Reserve idempotency key after approval check so failed approval does not pin the key.
	if req.IdempotencyKey != "" {
		ttl := idempotency.DefaultTTL
		if op.Idempotency.TTLSeconds > 0 {
			ttl = time.Duration(op.Idempotency.TTLSeconds) * time.Second
		}
		if err := rt.deps.Idempotency.Begin(ctx, idemKey, idemFP, ttl); err != nil {
			if errors.Is(err, core.ErrAlreadyExists) {
				return rt.deny(ctx, req, id, op, riskLevel, "idempotency", core.ReasonIdempotencyConflict, err.Error(), start, "")
			}
			return rt.deny(ctx, req, id, op, riskLevel, "idempotency", core.ReasonInternal, err.Error(), start, "")
		}
		idemBegin = true
		defer func() {
			if idemBegin {
				_ = rt.deps.Idempotency.Abort(ctx, idemKey)
			}
		}()
	}

	// 13. Claim approval immediately before the handler (single-use burn).
	// Concurrent Consume: exactly one wins. Handler failure still burns the
	// token (fail closed against double money side-effects).
	if apr.Required && apr.Approved && req.ApprovalToken != "" {
		if err := rt.deps.Approval.Consume(ctx, id, op, req.Boundary, req.ApprovalToken); err != nil {
			return rt.deny(ctx, req, id, op, riskLevel, "approval", core.ReasonApprovalDenied, "approval consume failed: "+err.Error(), start, "")
		}
	}

	// 14. Execute
	handler, err := rt.deps.Registry.Handler(op.Name)
	if err != nil {
		return rt.deny(ctx, req, id, op, riskLevel, "execute", core.ReasonHandlerMissing, err.Error(), start, "")
	}
	ec := &core.ExecutionContext{
		Ctx:       ctx,
		Identity:  id,
		Boundary:  req.Boundary,
		Operation: op,
		Resource:  req.Resource,
		Input:     req.Input,
		TraceID:   req.TraceID,
		Risk:      riskLevel,
	}
	// Fail closed if the context was canceled while the gates ran (before side effects).
	if err := ctx.Err(); err != nil {
		if quotaCharged {
			rt.refundQuota(ctx, id, req.Boundary, op.Name)
		}
		return rt.deny(ctx, req, id, op, riskLevel, "execute", core.ReasonContextCanceled, ctxErrMessage(err), start, "")
	}
	result, err := handler(ec)
	if err != nil {
		// Execution failed: refund the quota charged above so failing handlers
		// do not drain quota. Approval is already burned (fail closed).
		if quotaCharged {
			rt.refundQuota(ctx, id, req.Boundary, op.Name)
		}
		return rt.deny(ctx, req, id, op, riskLevel, "execute", core.ReasonExecutionFailed, err.Error(), start, "")
	}
	if result == nil {
		result = &core.Result{Output: map[string]any{}}
	}

	// 14. Filter output (field authz + secrets)
	filtered, err := rt.deps.Fields.Filter(id, req.Boundary, op.Name, req.Fields, op.SensitiveFields, result.Output)
	if err != nil {
		// Fail closed: empty output rather than leak
		filtered = map[string]any{}
	}
	filtered = guardrails.RedactSecretPatterns(filtered)

	// 15. Audit allow. Fail closed: an emit error converts the allow into a
	// deny (ReasonInternal, no output; the handler's side effects already
	// happened — that is the documented fail-closed trade-off). Approval is
	// already burned so a retry cannot double-execute.
	auditID, aerr := rt.audit(ctx, req, id, op, riskLevel, core.DecisionAllow, "execute", "allow", "execution succeeded", start, "")
	if aerr != nil {
		log.Printf("loom: audit emit failed on allow path (failing closed): %v", aerr)
		// Do not Abort idempotency after successful handler — prevents a second side effect.
		if idemBegin {
			// Best-effort: leave key in-flight so parallel retries conflict.
			idemBegin = false
		}
		return rt.deny(ctx, req, id, op, riskLevel, "audit", core.ReasonInternal, "audit emit failed: "+aerr.Error(), start, "")
	}

	resp = core.Response{
		Allowed:  true,
		Decision: core.DecisionAllow,
		Output:   filtered,
		TraceID:  req.TraceID,
		AuditID:  auditID,
		Risk:     riskLevel,
	}

	// Complete idempotency. On failure: log loudly, do NOT Abort (would enable
	// a second side-effect after TTL). Client still receives allow.
	if idemBegin {
		ttl := idempotency.DefaultTTL
		if op.Idempotency.TTLSeconds > 0 {
			ttl = time.Duration(op.Idempotency.TTLSeconds) * time.Second
		}
		if err := rt.deps.Idempotency.Complete(ctx, idemKey, &idempotency.Stored{
			Fingerprint: idemFP,
			Response:    resp,
			StoredAt:    rt.deps.Clock(),
			ExpiresAt:   rt.deps.Clock().Add(ttl),
		}); err != nil {
			log.Printf("loom: CRITICAL idempotency complete failed (key held in-flight): %v", err)
		}
		idemBegin = false
	}
	return resp
}

func (rt *Runtime) authenticate(ctx context.Context, req core.Request) (core.Identity, error) {
	if req.Credentials.Token == "" && req.Credentials.Scheme == "" {
		if rt.deps.AllowAnonymous {
			return core.Identity{
				ID:         "anonymous",
				Type:       "anonymous",
				AuthMethod: "none",
			}, nil
		}
		return core.Identity{}, fmt.Errorf("credentials required")
	}
	return rt.deps.Verifier.Authenticate(ctx, req.Credentials)
}

func (rt *Runtime) deny(
	ctx context.Context,
	req core.Request,
	id core.Identity,
	op *core.Operation,
	riskLevel core.RiskLevel,
	step, reason, message string,
	start time.Time,
	priorAudit string,
) core.Response {
	// Caller-facing denial carries only static per-reason text (+ hint/retryable);
	// the detailed message may contain internals and goes to the audit record only.
	denial := core.SafeDenial(step, reason)
	// The response is already a deny, so an audit emit error changes nothing
	// for the caller — but it must be logged, not silently dropped.
	auditID, aerr := rt.audit(ctx, req, id, op, riskLevel, core.DecisionDeny, step, reason, message, start, priorAudit)
	if aerr != nil {
		log.Printf("loom: audit emit failed on deny path: %v", aerr)
	}
	return core.Response{
		Allowed:  false,
		Decision: core.DecisionDeny,
		Denial:   denial,
		TraceID:  req.TraceID,
		AuditID:  auditID,
		Risk:     riskLevel,
		Output:   nil,
	}
}

func (rt *Runtime) audit(
	ctx context.Context,
	req core.Request,
	id core.Identity,
	op *core.Operation,
	riskLevel core.RiskLevel,
	decision core.Decision,
	step, reason, message string,
	start time.Time,
	priorAudit string,
) (string, error) {
	opName := req.Operation
	if op != nil {
		opName = op.Name
	}
	res := ""
	if req.Resource != nil {
		res = req.Resource.String()
	}
	var durMS int64
	if !start.IsZero() {
		durMS = rt.deps.Clock().Sub(start).Milliseconds()
	}
	ev := audit.Event{
		TraceID:    req.TraceID,
		Decision:   decision.String(),
		Reason:     reason,
		Step:       step,
		Message:    message,
		Principal:  string(id.ID),
		Delegator:  string(id.Delegator),
		Boundary:   string(req.Boundary),
		TenantID:   string(req.Boundary),
		Operation:  opName,
		Resource:   res,
		Risk:       riskLevel.String(),
		Input:      req.Input,
		Metadata:   req.Metadata,
		DurationMS: durMS,
		AuthMethod: id.AuthMethod,
		// Links a replay (or related event) to the original execution's audit ID.
		PriorAuditID: priorAudit,
	}
	return rt.deps.Audit.Emit(ctx, ev)
}

// panicDeny builds the recovery response for a pipeline panic. If deny/audit
// themselves panic during recovery (e.g. a broken Clock or audit sink), the
// second-level recover still upholds the "never panics out" contract with a
// minimal static deny (no audit — audit may be what is panicking).
func (rt *Runtime) panicDeny(ctx context.Context, req core.Request, rec any, start time.Time) (resp core.Response) {
	defer func() {
		if r2 := recover(); r2 != nil {
			resp = core.Response{
				Allowed:  false,
				Decision: core.DecisionDeny,
				Denial:   core.SafeDenial("execute", core.ReasonInternal),
				TraceID:  req.TraceID,
			}
		}
	}()
	return rt.deny(ctx, req, core.Identity{}, nil, core.RiskLow, "execute", core.ReasonInternal,
		fmt.Sprintf("panic: %v", rec), start, "")
}

// ctxErrMessage distinguishes deadline vs cancel for the audit record only.
func ctxErrMessage(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "context deadline exceeded"
	}
	return "context canceled"
}

// refundQuota rolls back the quota unit charged for an execution that failed
// or never ran. Best-effort: refund errors are logged, never denied.
func (rt *Runtime) refundQuota(ctx context.Context, id core.Identity, boundary core.BoundaryID, op string) {
	if err := rt.deps.Quotas.Refund(ctx, id, boundary, op, 1); err != nil {
		log.Printf("loom: quota refund failed for %s op %s: %v", id.ID, op, err)
	}
}
