// Package app is the primary way to build with Loom without an HTTP API.
//
// Embed Loom in your process:
//
//	a, err := app.New(app.Config{...})
//	a.OpenDB("main", "pgx", dsn, db.Options{AllowedTables: []string{"orders"}})
//	a.EnableDBOps()
//	// grant principals...
//	resp := a.Call(ctx, core.Request{Operation: "db.query", ...})
//
// HTTP/MCP/Weft are optional adapters on top of the same Runtime.
package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/boundary"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/guardrails"
	"github.com/loreste/loom/idempotency"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/quotas"
	"github.com/loreste/loom/resource"
	"github.com/loreste/loom/risk"
	"github.com/loreste/loom/runtime"
	"github.com/loreste/loom/sdk/go/loom"
)

// Config for an embedded Loom app (no server required).
type Config struct {
	// AuditSink optional; default memory.
	AuditSink audit.Sink
	// AllowAnonymous defaults false.
	AllowAnonymous bool
	// Environment is an application-owned deployment label. Production requires
	// an injected verifier and validates durable capabilities per operation.
	Environment string
	// RequireDurableSecurityState rejects process-local state globally. Use it
	// when every registered operation must have durable security backends.
	RequireDurableSecurityState bool
	// Security dependencies are injectable so identity and durable stores remain
	// application configuration rather than hidden package defaults.
	IdentityVerifier identity.Verifier
	ApprovalEngine   approval.Engine
	QuotaLimiter     quotas.Limiter
	IdempotencyStore idempotency.Store
	ExecutionStore   execution.Store
	BoundaryChecker  boundary.Checker
	PolicyEngine     policy.Engine
	ResourceChecker  resource.Checker
	TenantResolver   runtime.TenantResolver
	// Tracer enables per-stage distributed tracing. See observability/otel.
	Tracer           runtime.Tracer
}

// App is an in-process Loom application.
type App struct {
	Runtime          *runtime.Runtime
	Registry         *core.Registry
	Verifier         *identity.MemoryVerifier
	Boundary         *boundary.MemoryChecker
	Policy           *policy.MemoryEngine
	Resources        *resource.MemoryChecker
	Fields           *resource.FieldFilter
	Approval         *approval.MemoryEngine
	Quotas           *quotas.MemoryLimiter
	Idempotency      *idempotency.MemoryStore
	Guardrails       *guardrails.Chain
	DBs              *db.Registry
	AuditSink        *audit.MemorySink
	VerifierEngine   identity.Verifier
	BoundaryChecker  boundary.Checker
	PolicyEngine     policy.Engine
	ResourceChecker  resource.Checker
	ApprovalEngine   approval.Engine
	TenantResolver   runtime.TenantResolver
	QuotaLimiter     quotas.Limiter
	IdempotencyStore idempotency.Store
	ExecutionStatus  execution.Store
	Metrics          *runtime.Metrics
	client           *loom.Client
}

// New constructs a deny-by-default embedded runtime.
func New(cfg Config) (*App, error) {
	reg := core.NewRegistry()
	ver := identity.NewMemoryVerifier()
	bnd := boundary.NewMemoryChecker()
	pol := policy.NewMemoryEngine()
	res := resource.NewMemoryChecker()
	fields := resource.NewFieldFilter()
	apr := approval.NewMemoryEngine()
	q := quotas.NewMemoryLimiter()
	idem := idempotency.NewMemoryStore()
	memSink := &audit.MemorySink{}
	var sink audit.Sink = memSink
	production := isProductionEnvironment(cfg.Environment)
	if cfg.AuditSink != nil {
		if cfg.RequireDurableSecurityState || production {
			sink = cfg.AuditSink
		} else {
			sink = &audit.MultiSink{Sinks: []audit.Sink{memSink, cfg.AuditSink}}
		}
	}
	verifier := cfg.IdentityVerifier
	if verifier == nil {
		verifier = ver
	}
	boundaryChecker := cfg.BoundaryChecker
	if boundaryChecker == nil {
		boundaryChecker = bnd
	}
	policyEngine := cfg.PolicyEngine
	if policyEngine == nil {
		policyEngine = pol
	}
	resourceChecker := cfg.ResourceChecker
	if resourceChecker == nil {
		resourceChecker = res
	}
	approvalEngine := cfg.ApprovalEngine
	if approvalEngine == nil {
		approvalEngine = apr
	}
	quotaLimiter := cfg.QuotaLimiter
	if quotaLimiter == nil {
		quotaLimiter = q
	}
	idempotencyStore := cfg.IdempotencyStore
	if idempotencyStore == nil {
		idempotencyStore = idem
	}
	executionStore := cfg.ExecutionStore
	if executionStore == nil {
		executionStore = execution.NewMemoryStore()
	}
	if production {
		if cfg.AllowAnonymous {
			return nil, fmt.Errorf("%w: anonymous access is not allowed in production", core.ErrInvalidArgument)
		}
		if cfg.IdentityVerifier == nil {
			return nil, fmt.Errorf("%w: production requires an injected identity verifier", core.ErrInvalidArgument)
		}
	}
	if cfg.RequireDurableSecurityState {
		for name, dep := range map[string]any{
			"approval":    approvalEngine,
			"quotas":      quotaLimiter,
			"idempotency": idempotencyStore,
			"execution":   executionStore,
			"audit":       sink,
		} {
			durable, ok := dep.(interface{ Durable() bool })
			if !ok || !durable.Durable() {
				return nil, fmt.Errorf("%w: %s dependency is process-local; inject a durable implementation", core.ErrInvalidArgument, name)
			}
		}
	}
	gr := guardrails.DefaultChain()
	metrics := runtime.NewMetrics()
	// SQL-bearing ops get schema + secrets; database package enforces SQL class.

	mode := runtime.ModeDevelopment
	if production || cfg.RequireDurableSecurityState {
		mode = runtime.ModeProduction
	}
	var recovery idempotency.RecoveryQueue
	if q, ok := executionStore.(idempotency.RecoveryQueue); ok {
		recovery = q
	} else if q, ok := idempotencyStore.(idempotency.RecoveryQueue); ok {
		recovery = q
	}
	rt, err := runtime.New(runtime.Dependencies{
		Mode:                   mode,
		Registry:               reg,
		Verifier:               verifier,
		Boundary:               boundaryChecker,
		Policy:                 policyEngine,
		Resources:              resourceChecker,
		Fields:                 fields,
		Guardrails:             gr,
		Risk:                   risk.NewSimpleEngine(),
		RiskBlock:              &risk.Blocker{MaxAllowed: core.RiskCritical},
		Approval:               approvalEngine,
		Quotas:                 quotaLimiter,
		Idempotency:            idempotencyStore,
		IdempotencyRecovery:    recovery,
		ExecutionStatus:        executionStore,
		Audit:                  audit.NewLogger(sink),
		Observer:               metrics,
		Tenant:                 cfg.TenantResolver,
		Tracer:                 cfg.Tracer,
		AllowAnonymous:         cfg.AllowAnonymous,
		DeferDurableValidation: production && !cfg.RequireDurableSecurityState,
	})
	if err != nil {
		return nil, err
	}
	a := &App{
		Runtime:          rt,
		Registry:         reg,
		Verifier:         ver,
		Boundary:         bnd,
		Policy:           pol,
		Resources:        res,
		Fields:           fields,
		Approval:         apr,
		Quotas:           q,
		Idempotency:      idem,
		Guardrails:       gr,
		DBs:              db.NewRegistry(),
		AuditSink:        memSink,
		VerifierEngine:   verifier,
		BoundaryChecker:  boundaryChecker,
		PolicyEngine:     policyEngine,
		ResourceChecker:  resourceChecker,
		ApprovalEngine:   approvalEngine,
		TenantResolver:   cfg.TenantResolver,
		QuotaLimiter:     quotaLimiter,
		IdempotencyStore: idempotencyStore,
		ExecutionStatus:  executionStore,
		Metrics:          metrics,
		client:           loom.NewClient(rt),
	}
	return a, nil
}

func isProductionEnvironment(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "production", "prod", "staging":
		return true
	default:
		return false
	}
}

// Close releases DB pools.
func (a *App) Close() error {
	if a == nil {
		return nil
	}
	return a.DBs.Close()
}

// Call is the only application entrypoint (same as Runtime.Execute).
func (a *App) Call(ctx context.Context, req core.Request) core.Response {
	if a == nil || a.client == nil {
		return core.Response{
			Allowed:  false,
			Decision: core.DecisionDeny,
			Denial:   core.NewDenial("app", core.ReasonInternal, "app not configured", nil),
		}
	}
	if req.Metadata == nil {
		req.Metadata = map[string]string{}
	}
	if req.Metadata["adapter"] == "" {
		req.Metadata["adapter"] = "embed"
	}
	return a.client.Call(ctx, req)
}

// Register adds a custom governed operation + handler.
func (a *App) Register(op *core.Operation, h core.Handler) error {
	if a == nil || a.Runtime == nil {
		return fmt.Errorf("%w: app runtime is not configured", core.ErrInvalidArgument)
	}
	if err := a.Runtime.ValidateOperation(op); err != nil {
		return err
	}
	return a.Registry.Register(op, h)
}

// OpenDB registers a named database pool (DSN not retained).
func (a *App) OpenDB(name, driver, dsn string, opts db.Options) error {
	return a.DBs.Open(name, driver, dsn, opts)
}

// EnableDBOps registers db.query and db.exec governed operations.
func (a *App) EnableDBOps() error {
	return db.RegisterOps(a.Registry, a.DBs)
}

// Principal helpers for embedding.

// AddUser registers a static bearer principal (dev/simple deploy).
func (a *App) AddUser(id core.PrincipalID, token string, home core.BoundaryID, caps []string) error {
	registrar, ok := a.VerifierEngine.(interface {
		Register(identity.StaticPrincipal) error
	})
	if !ok {
		return fmt.Errorf("%w: configured verifier does not support static users", core.ErrInvalidArgument)
	}
	if err := registrar.Register(identity.StaticPrincipal{
		ID: id, Token: token, Boundary: home, Type: "user", Capabilities: caps,
	}); err != nil {
		return err
	}
	if home != "" {
		return a.Boundary.Grant(id, home)
	}
	return nil
}

// GrantBoundary adds membership.
func (a *App) GrantBoundary(id core.PrincipalID, b core.BoundaryID) error {
	grantor, ok := a.BoundaryChecker.(interface {
		Grant(core.PrincipalID, core.BoundaryID) error
	})
	if !ok {
		return fmt.Errorf("%w: configured boundary checker does not support grants", core.ErrInvalidArgument)
	}
	return grantor.Grant(id, b)
}

// AllowPolicy adds an explicit allow rule.
func (a *App) AllowPolicy(rule policy.Rule) error {
	adder, ok := a.PolicyEngine.(interface{ AddRule(policy.Rule) error })
	if !ok {
		return fmt.Errorf("%w: configured policy engine does not support grants", core.ErrInvalidArgument)
	}
	return adder.AddRule(rule)
}

// AllowResource adds a resource ACL rule.
func (a *App) AllowResource(rule resource.Rule) error {
	grantor, ok := a.ResourceChecker.(interface{ Grant(resource.Rule) error })
	if !ok {
		return fmt.Errorf("%w: configured resource checker does not support grants", core.ErrInvalidArgument)
	}
	return grantor.Grant(rule)
}

// AllowFields grants output fields.
func (a *App) AllowFields(id core.PrincipalID, b core.BoundaryID, op string, fields []string) error {
	return a.Fields.GrantFields(id, b, op, fields)
}

// AllowInputFields grants fields a caller may provide to an operation. Input
// grants are independent from output projection grants.
func (a *App) AllowInputFields(id core.PrincipalID, b core.BoundaryID, op string, fields []string) error {
	return a.Fields.GrantInputFields(id, b, op, fields)
}

// IssueApproval issues a single-use approval token (tests/admin tooling).
func (a *App) IssueApproval(token string, principal core.PrincipalID, op string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	return a.IssueApprovalVersioned(token, principal, op, core.DefaultOperationVersion, boundary, maxRisk, ttl)
}

// IssueApprovalVersioned binds an approval token to an exact operation version.
func (a *App) IssueApprovalVersioned(token string, principal core.PrincipalID, op string, version string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	if a == nil || a.ApprovalEngine == nil {
		return fmt.Errorf("%w: approval issuer is not configured", core.ErrInvalidArgument)
	}
	if versioned, ok := a.ApprovalEngine.(approval.VersionedIssuer); ok {
		return versioned.IssueVersioned(token, principal, op, version, boundary, maxRisk, ttl)
	}
	if core.NormalizeOperationVersion(version) != core.DefaultOperationVersion {
		return fmt.Errorf("%w: approval issuer does not support operation versions", core.ErrInvalidArgument)
	}
	issuer, ok := a.ApprovalEngine.(approval.Issuer)
	if !ok {
		return fmt.Errorf("%w: approval issuer is not configured", core.ErrInvalidArgument)
	}
	return issuer.Issue(token, principal, op, boundary, maxRisk, ttl)
}

// DBExecutor returns a scoped DB handle for custom handlers (still SQL-guarded).
// Prefer governed db.query/db.exec for most app code.
func (a *App) DBExecutor(name string, id core.Identity, boundary core.BoundaryID) (*db.Executor, error) {
	return a.DBs.ExecutorFor(name, id, boundary)
}

// Must is a helper for main().
func Must(a *App, err error) *App {
	if err != nil {
		panic(err)
	}
	return a
}
