package runtime

import (
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

// TestStack is a fully wired in-memory stack for tests and examples.
// Still deny-by-default until rules/principals are granted.
type TestStack struct {
	Runtime    *Runtime
	Registry   *core.Registry
	Verifier   *identity.MemoryVerifier
	Delegation *identity.MemoryDelegation
	Boundary   *boundary.MemoryChecker
	Policy     *policy.MemoryEngine
	Resources  *resource.MemoryChecker
	Fields     *resource.FieldFilter
	Guardrails *guardrails.Chain
	Approval    *approval.MemoryEngine
	Quotas      *quotas.MemoryLimiter
	Idempotency *idempotency.MemoryStore
	AuditSink  *audit.MemorySink
	RiskBlock  *risk.Blocker
}

// NewTestStack constructs a deny-all stack ready for explicit grants.
func NewTestStack() (*TestStack, error) {
	reg := core.NewRegistry()
	ver := identity.NewMemoryVerifier()
	del := identity.NewMemoryDelegation()
	bnd := boundary.NewMemoryChecker()
	pol := policy.NewMemoryEngine()
	res := resource.NewMemoryChecker()
	fields := resource.NewFieldFilter()
	gr := guardrails.DefaultChain()
	apr := approval.NewMemoryEngine()
	q := quotas.NewMemoryLimiter()
	idem := idempotency.NewMemoryStore()
	sink := &audit.MemorySink{}
	block := &risk.Blocker{MaxAllowed: core.RiskCritical} // allow up to critical if approval ok

	rt, err := New(Dependencies{
		Registry:    reg,
		Verifier:    ver,
		Delegation:  del,
		Boundary:    bnd,
		Policy:      pol,
		Resources:   res,
		Fields:      fields,
		Guardrails:  gr,
		Risk:        risk.NewSimpleEngine(),
		RiskBlock:   block,
		Approval:    apr,
		Quotas:      q,
		Idempotency: idem,
		Audit:       audit.NewLogger(sink),
	})
	if err != nil {
		return nil, err
	}
	return &TestStack{
		Runtime:     rt,
		Registry:    reg,
		Verifier:    ver,
		Delegation:  del,
		Boundary:    bnd,
		Policy:      pol,
		Resources:   res,
		Fields:      fields,
		Guardrails:  gr,
		Approval:    apr,
		Quotas:      q,
		Idempotency: idem,
		AuditSink:   sink,
		RiskBlock:   block,
	}, nil
}
