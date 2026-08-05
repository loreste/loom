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
	"github.com/loreste/loom/execution"
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

// Mode controls whether process-local security state may be used.
type Mode string

const (
	ModeDevelopment Mode = "development"
	ModeTest        Mode = "test"
	ModeProduction  Mode = "production"
)

type Dependencies struct {
	Mode                Mode
	Registry            *core.Registry
	Verifier            identity.Verifier
	Delegation          identity.DelegationValidator // optional; required only if request has delegation
	Boundary            boundary.Checker
	Policy              policy.Engine
	Resources           resource.Checker
	Fields              *resource.FieldFilter
	Guardrails          *guardrails.Chain
	Risk                risk.Engine
	RiskBlock           *risk.Blocker // optional hard risk ceiling
	Approval            approval.Engine
	Quotas              quotas.Limiter
	Idempotency         idempotency.Store
	IdempotencyRecovery idempotency.RecoveryQueue
	ExecutionStatus     execution.Store
	Audit               *audit.Logger
	Observer            Observer

	// AllowAnonymous is false by default. If true, empty credentials get a synthetic
	// unauthenticated identity that still must pass policy (almost always deny).
	AllowAnonymous bool
	// DeferDurableValidation allows a production app to start before operation
	// registration. Register-time validation then checks only the capabilities
	// required by each operation.
	DeferDurableValidation bool
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
	if deps.Mode == ModeProduction && !deps.DeferDurableValidation {
		if deps.Approval == nil || !durable(deps.Approval) {
			return nil, fmt.Errorf("%w: production requires durable approval state", core.ErrInvalidArgument)
		}
		if deps.Quotas == nil || !durable(deps.Quotas) {
			return nil, fmt.Errorf("%w: production requires durable quota state", core.ErrInvalidArgument)
		}
		if deps.Idempotency == nil || !durable(deps.Idempotency) {
			return nil, fmt.Errorf("%w: production requires durable idempotency state", core.ErrInvalidArgument)
		}
		if deps.Audit == nil || deps.Audit.Sink == nil || !durable(deps.Audit.Sink) {
			return nil, fmt.Errorf("%w: production requires durable audit state", core.ErrInvalidArgument)
		}
	}
	if deps.Fields == nil {
		// Fail closed field filter: strip all.
		deps.Fields = resource.NewFieldFilter()
	}
	if deps.Mode == ModeProduction && deps.Guardrails != nil && deps.Guardrails.Len() == 0 {
		return nil, fmt.Errorf("%w: production requires a non-empty guardrail chain", core.ErrInvalidArgument)
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
	if deps.ExecutionStatus == nil {
		deps.ExecutionStatus = execution.NewMemoryStore()
	}
	if deps.Audit == nil {
		deps.Audit = audit.NewLogger(&audit.MemorySink{})
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	return &Runtime{deps: deps}, nil
}

// ValidateOperation checks production capabilities required by one operation.
// It is safe to call during registration and again at execution time.
func (rt *Runtime) ValidateOperation(op *core.Operation) error {
	if rt == nil || op == nil {
		return fmt.Errorf("%w: operation is required", core.ErrInvalidArgument)
	}
	if rt.deps.Mode != ModeProduction {
		return nil
	}
	sideEffect := op.HasEffect(core.EffectWrite) || op.HasEffect(core.EffectDelete) ||
		op.HasEffect(core.EffectExec) || op.HasEffect(core.EffectMoney) || op.HasEffect(core.EffectAdmin)
	if !sideEffect {
		return nil
	}
	if rt.deps.ExecutionStatus == nil || !durable(rt.deps.ExecutionStatus) {
		return fmt.Errorf("%w: %s requires durable execution status", core.ErrInvalidArgument, op.Name)
	}
	if rt.deps.Audit == nil || rt.deps.Audit.Sink == nil || !durable(rt.deps.Audit.Sink) {
		return fmt.Errorf("%w: %s requires durable audit", core.ErrInvalidArgument, op.Name)
	}
	if op.Idempotency.Required && !durable(rt.deps.Idempotency) {
		return fmt.Errorf("%w: %s requires durable idempotency", core.ErrInvalidArgument, op.Name)
	}
	approvalRequired := op.Approval.Required || op.Approval.MinRisk > core.RiskLow || len(op.Approval.Effects) > 0
	if approvalRequired && !durable(rt.deps.Approval) {
		return fmt.Errorf("%w: %s requires durable approval", core.ErrInvalidArgument, op.Name)
	}
	if op.Quota.Enabled && !durable(rt.deps.Quotas) {
		return fmt.Errorf("%w: %s requires durable quota state", core.ErrInvalidArgument, op.Name)
	}
	return nil
}

// ExecutionStatus returns the caller-safe status record for an execution ID.
// Authorization for remote callers belongs to the adapter; in-process callers
// should only expose this method to trusted operational code.
func (rt *Runtime) ExecutionStatus(ctx context.Context, executionID string) (execution.Record, error) {
	if rt == nil || rt.deps.ExecutionStatus == nil {
		return execution.Record{}, fmt.Errorf("%w: execution status store is not configured", core.ErrInvalidArgument)
	}
	record, ok, err := rt.deps.ExecutionStatus.Get(ctx, executionID)
	if err != nil {
		return execution.Record{}, err
	}
	if !ok {
		return execution.Record{}, fmt.Errorf("%w: execution %q", core.ErrNotFound, executionID)
	}
	return record, nil
}

// ReconcileExecution confirms whether an executed_unconfirmed handler attempt
// completed. It never runs the handler again.
func (rt *Runtime) ReconcileExecution(ctx context.Context, executionID string, outcome core.Outcome, note string) (execution.Record, error) {
	if rt == nil || rt.deps.ExecutionStatus == nil {
		return execution.Record{}, fmt.Errorf("%w: execution status store is not configured", core.ErrInvalidArgument)
	}
	return rt.deps.ExecutionStatus.Reconcile(ctx, executionID, outcome, note)
}

// RetryExecutionRecording requeues only the durable idempotency/audit record;
// it never retries the business handler or its side effect.
func (rt *Runtime) RetryExecutionRecording(ctx context.Context, executionID string) error {
	record, err := rt.ExecutionStatus(ctx, executionID)
	if err != nil {
		return err
	}
	if record.IdempotencyKey == "" || record.Fingerprint == "" {
		return fmt.Errorf("%w: execution has no pending idempotency recording", core.ErrInvalidArgument)
	}
	if rt.deps.IdempotencyRecovery == nil {
		return fmt.Errorf("%w: idempotency recovery queue is not configured", core.ErrInvalidArgument)
	}
	if err := rt.deps.IdempotencyRecovery.Enqueue(ctx, idempotency.RecoveryRecord{
		ExecutionID: executionID, Key: record.IdempotencyKey,
		Fingerprint: record.Fingerprint, Response: record.Response,
		CreatedAt: rt.deps.Clock(),
	}); err != nil {
		return err
	}
	_, err = rt.deps.ExecutionStatus.MarkRecoveryQueued(ctx, executionID)
	return err
}

// ExecutionStatusFor authenticates a caller and permits the execution owner
// or an explicit execution.status capability to read a status record.
func (rt *Runtime) ExecutionStatusFor(ctx context.Context, credentials core.Credentials, executionID string) (execution.Record, error) {
	identity, record, err := rt.authorizeExecution(ctx, credentials, executionID)
	if err != nil {
		return execution.Record{}, err
	}
	if identity.ID != core.PrincipalID(record.Principal) && !hasCapability(identity, "execution.status") {
		return execution.Record{}, fmt.Errorf("%w: execution status access denied", core.ErrUnauthorized)
	}
	return record, nil
}

// ReconcileExecutionFor authenticates a caller before confirming an outcome.
func (rt *Runtime) ReconcileExecutionFor(ctx context.Context, credentials core.Credentials, executionID string, outcome core.Outcome, note string) (execution.Record, error) {
	identity, record, err := rt.authorizeExecution(ctx, credentials, executionID)
	if err != nil {
		return execution.Record{}, err
	}
	if identity.ID != core.PrincipalID(record.Principal) && !hasCapability(identity, "execution.reconcile") {
		return execution.Record{}, fmt.Errorf("%w: execution reconciliation access denied", core.ErrUnauthorized)
	}
	return rt.ReconcileExecution(ctx, executionID, outcome, note)
}

// RetryExecutionRecordingFor authenticates a caller before requeueing durable
// recording work. The handler is never rerun.
func (rt *Runtime) RetryExecutionRecordingFor(ctx context.Context, credentials core.Credentials, executionID string) error {
	identity, record, err := rt.authorizeExecution(ctx, credentials, executionID)
	if err != nil {
		return err
	}
	if identity.ID != core.PrincipalID(record.Principal) && !hasCapability(identity, "execution.reconcile") {
		return fmt.Errorf("%w: execution retry access denied", core.ErrUnauthorized)
	}
	return rt.RetryExecutionRecording(ctx, executionID)
}

func (rt *Runtime) authorizeExecution(ctx context.Context, credentials core.Credentials, executionID string) (core.Identity, execution.Record, error) {
	if rt == nil || rt.deps.Verifier == nil {
		return core.Identity{}, execution.Record{}, fmt.Errorf("%w: identity verifier is not configured", core.ErrInvalidArgument)
	}
	identity, err := rt.deps.Verifier.Authenticate(ctx, credentials)
	if err != nil {
		return core.Identity{}, execution.Record{}, fmt.Errorf("%w: credentials", core.ErrUnauthorized)
	}
	record, err := rt.ExecutionStatus(ctx, executionID)
	if err != nil {
		return core.Identity{}, execution.Record{}, err
	}
	return identity, record, nil
}

func hasCapability(identity core.Identity, capability string) bool {
	for _, candidate := range identity.Capabilities {
		if candidate == capability {
			return true
		}
	}
	return identity.Type == "system"
}

func durable(value any) bool {
	d, ok := value.(interface{ Durable() bool })
	return ok && d.Durable()
}

// Execute runs the full permission pipeline. Never panics out; recovers to deny.
func (rt *Runtime) Execute(ctx context.Context, req core.Request) (resp core.Response) {
	executionID := core.NewTraceID()
	selectedVersion := core.NormalizeOperationVersion(req.OperationVersion)
	req.ExecutionID = executionID
	var executionRecord execution.Record
	var executionRecordStarted bool
	defer func() {
		if resp.ExecutionID == "" {
			resp.ExecutionID = executionID
		}
		if resp.Outcome == "" {
			if resp.Allowed {
				resp.Outcome = core.OutcomeAllowed
			} else {
				resp.Outcome = core.OutcomeDenied
			}
		}
		if resp.OperationVersion == "" {
			resp.OperationVersion = selectedVersion
		}
		if executionRecordStarted && rt != nil && rt.deps.ExecutionStatus != nil {
			executionRecord.Response = resp
			executionRecord.Outcome = resp.Outcome
			executionRecord.State = execution.StateFor(resp)
			executionRecord.UpdatedAt = rt.deps.Clock()
			if err := rt.deps.ExecutionStatus.Put(context.Background(), executionRecord); err != nil {
				log.Printf("loom: execution status update failed for %s: %v", executionID, err)
			}
		}
	}()
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

	if req.BoundaryContext != nil {
		if !req.BoundaryContext.Valid() || req.BoundaryContext.ID != req.Boundary {
			return rt.deny(ctx, req, id, nil, core.RiskLow, "boundary", core.ReasonBoundaryViolation, "structured boundary does not match boundary id", start, "")
		}
	}

	// 3. Boundary
	if err := rt.deps.Boundary.Allow(ctx, id, req.Boundary); err != nil {
		return rt.deny(ctx, req, id, nil, core.RiskLow, "boundary", core.ReasonBoundaryViolation, err.Error(), start, "")
	}

	// Resolve operation — unknown ⇒ deny
	op, err := rt.deps.Registry.GetVersion(req.Operation, req.OperationVersion)
	if err != nil {
		return rt.deny(ctx, req, id, nil, core.RiskLow, "operation", core.ReasonOperationUnknown, err.Error(), start, "")
	}
	selectedVersion = op.Version

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

	// 6. Input field permission. A structurally valid field is not necessarily
	// writable by this caller (for example tenant_id, role, or credit_limit).
	if rt.deps.Fields.HasInputGrant(id, req.Boundary, op.Name) {
		if err := rt.deps.Fields.AuthorizeInput(id, req.Boundary, op.Name, op.SensitiveFields, req.Input); err != nil {
			return rt.deny(ctx, req, id, op, core.RiskLow, "input_fields", core.ReasonFieldDenied, err.Error(), start, "")
		}
	}

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
	if err := rt.ValidateOperation(op); err != nil {
		return rt.deny(ctx, req, id, op, core.RiskLow, "production", core.ReasonInternal, err.Error(), start, "")
	}
	if err := rt.deps.Guardrails.ValidateOperation(op); err != nil {
		return rt.deny(ctx, req, id, op, core.RiskLow, "guardrails", core.ReasonGuardrail, err.Error(), start, "")
	}
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
		idemKey = idempotency.CompositeKeyVersioned(id.ID, req.Boundary, op.Name, op.Version, req.IdempotencyKey)
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
			auditID, aerr := rt.audit(ctx, req, id, op, riskLevel, core.DecisionAllow, "idempotency", "allow", "idempotent replay", start, replay.AuditID, executionID)
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
	quotaEnabled := rt.deps.Mode != ModeProduction || op.Quota.Enabled
	if quotaEnabled {
		if err := rt.deps.Quotas.Allow(ctx, id, req.Boundary, op.Name, 1); err != nil {
			return rt.deny(ctx, req, id, op, riskLevel, "quotas", core.ReasonQuotaExceeded, err.Error(), start, "")
		}
		quotaCharged = true
	}

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
	handler, err := rt.deps.Registry.HandlerVersion(op.Name, op.Version)
	if err != nil {
		return rt.deny(ctx, req, id, op, riskLevel, "execute", core.ReasonHandlerMissing, err.Error(), start, "")
	}
	ec := &core.ExecutionContext{
		Ctx:             ctx,
		Identity:        id,
		Boundary:        req.Boundary,
		BoundaryContext: req.BoundaryContext,
		Operation:       op,
		Resource:        req.Resource,
		Input:           req.Input,
		TraceID:         req.TraceID,
		Risk:            riskLevel,
	}
	// Fail closed if the context was canceled while the gates ran (before side effects).
	if err := ctx.Err(); err != nil {
		if quotaCharged {
			rt.refundQuota(ctx, id, req.Boundary, op.Name)
		}
		return rt.deny(ctx, req, id, op, riskLevel, "execute", core.ReasonContextCanceled, ctxErrMessage(err), start, "")
	}
	executionRecord = execution.Record{
		ExecutionID: executionID, Operation: op.Name, OperationVersion: op.Version,
		Principal: string(id.ID), Boundary: string(req.Boundary), State: execution.StatePending,
		Response:       core.Response{ExecutionID: executionID, OperationVersion: op.Version},
		IdempotencyKey: idemKey, Fingerprint: idemFP, StartedAt: start,
	}
	if err := rt.deps.ExecutionStatus.Put(ctx, executionRecord); err != nil {
		return rt.deny(ctx, req, id, op, riskLevel, "execution_status", core.ReasonInternal, err.Error(), start, "")
	}
	executionRecordStarted = true
	result, err := handler(ec)
	if err != nil {
		// Execution failed: refund the quota charged above so failing handlers
		// do not drain quota. Approval is already burned (fail closed).
		if quotaCharged && op.Quota.RefundOnHandlerError {
			rt.refundQuota(ctx, id, req.Boundary, op.Name)
		}
		return rt.deny(ctx, req, id, op, riskLevel, "execute", core.ReasonExecutionFailed, err.Error(), start, "")
	}
	if result == nil {
		result = &core.Result{Output: map[string]any{}}
	}

	// 14. Validate and filter output. A declared output contract is mandatory
	// when present; malformed or unexpected handler output is never returned.
	if len(op.OutputSchema) > 0 {
		if err := guardrails.ValidateSchema(op.OutputSchema, result.Output); err != nil {
			return rt.deny(ctx, req, id, op, riskLevel, "output_schema", core.ReasonOutputFilter, err.Error(), start, "")
		}
	}
	filtered, err := rt.deps.Fields.Filter(id, req.Boundary, op.Name, req.Fields, op.SensitiveFields, result.Output)
	if err != nil {
		return rt.deny(ctx, req, id, op, riskLevel, "output_filter", core.ReasonOutputFilter, err.Error(), start, "")
	}
	filtered = guardrails.RedactSecretPatterns(filtered)

	// 15. Audit allow. Fail closed: an emit error converts the allow into a
	// deny (ReasonInternal, no output; the handler's side effects already
	// happened — that is the documented fail-closed trade-off). Approval is
	// already burned so a retry cannot double-execute.
	auditID, aerr := rt.audit(ctx, req, id, op, riskLevel, core.DecisionAllow, "execute", "allow", "execution succeeded", start, "", executionID)
	if aerr != nil {
		log.Printf("loom: audit emit failed on allow path (failing closed): %v", aerr)
		// Do not Abort idempotency after successful handler — prevents a second side effect.
		if idemBegin {
			// Best-effort: leave key in-flight so parallel retries conflict.
			idemBegin = false
		}
		return core.Response{
			Allowed:          false,
			Outcome:          core.OutcomeExecutedUnconfirmed,
			ExecutionID:      executionID,
			OperationVersion: op.Version,
			Decision:         core.DecisionDeny,
			Denial:           core.SafeDenial("audit", core.ReasonExecutedUnconfirmed),
			TraceID:          req.TraceID,
			Risk:             riskLevel,
		}
	}

	resp = core.Response{
		Allowed:          true,
		Outcome:          core.OutcomeAllowed,
		ExecutionID:      executionID,
		OperationVersion: op.Version,
		Decision:         core.DecisionAllow,
		Output:           filtered,
		TraceID:          req.TraceID,
		AuditID:          auditID,
		Risk:             riskLevel,
	}

	// Complete idempotency. On failure: log loudly, do NOT Abort (would enable
	// a second side-effect after TTL). Client still receives allow.
	if idemBegin {
		ttl := idempotency.DefaultTTL
		if op.Idempotency.TTLSeconds > 0 {
			ttl = time.Duration(op.Idempotency.TTLSeconds) * time.Second
		}
		stored := &idempotency.Stored{
			Fingerprint: idemFP,
			Response:    resp,
			StoredAt:    rt.deps.Clock(),
			ExpiresAt:   rt.deps.Clock().Add(ttl),
		}
		if err := rt.deps.Idempotency.Complete(ctx, idemKey, stored); err != nil {
			resp.ReliabilityWarning = "idempotency_completion_pending"
			log.Printf("loom: CRITICAL idempotency complete failed (key held in-flight): %v", err)
			if rt.deps.IdempotencyRecovery != nil {
				if qerr := rt.deps.IdempotencyRecovery.Enqueue(ctx, idempotency.RecoveryRecord{
					ExecutionID: executionID,
					Key:         idemKey,
					Fingerprint: idemFP,
					Response:    resp,
					CreatedAt:   rt.deps.Clock(),
				}); qerr != nil {
					log.Printf("loom: CRITICAL idempotency recovery enqueue failed: %v", qerr)
				}
			}
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
	auditID, aerr := rt.audit(ctx, req, id, op, riskLevel, core.DecisionDeny, step, reason, message, start, priorAudit, "")
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
	executionID string,
) (string, error) {
	if executionID == "" {
		executionID = req.ExecutionID
	}
	opName := req.Operation
	if op != nil {
		opName = op.Name
	}
	res := ""
	if req.Resource != nil {
		res = req.Resource.String()
	}
	boundaryType, parentType, parentID := "", "", ""
	tenantID := ""
	if id.Attributes != nil {
		tenantID = id.Attributes["tenant_id"]
	}
	if req.BoundaryContext != nil {
		boundaryType = req.BoundaryContext.Type
		parentType = req.BoundaryContext.ParentType
		parentID = string(req.BoundaryContext.ParentID)
		if tenantID == "" && req.BoundaryContext.Type == "tenant" {
			tenantID = string(req.BoundaryContext.ID)
		}
	}
	var durMS int64
	if !start.IsZero() {
		durMS = rt.deps.Clock().Sub(start).Milliseconds()
	}
	ev := audit.Event{
		ExecutionID:        executionID,
		TraceID:            req.TraceID,
		Decision:           decision.String(),
		Reason:             reason,
		Step:               step,
		Message:            message,
		Principal:          string(id.ID),
		Delegator:          string(id.Delegator),
		Boundary:           string(req.Boundary),
		BoundaryType:       boundaryType,
		BoundaryParentType: parentType,
		BoundaryParentID:   parentID,
		TenantID:           tenantID,
		Operation:          opName,
		Resource:           res,
		Risk:               riskLevel.String(),
		// Redact at the runtime boundary as well as inside the logger. A custom
		// audit sink must never receive unrestricted request input.
		Input:      guardrails.RedactSecrets(req.Input),
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
