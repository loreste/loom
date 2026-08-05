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
	"time"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/boundary"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
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
}

// App is an in-process Loom application.
type App struct {
	Runtime    *runtime.Runtime
	Registry   *core.Registry
	Verifier   *identity.MemoryVerifier
	Boundary   *boundary.MemoryChecker
	Policy     *policy.MemoryEngine
	Resources  *resource.MemoryChecker
	Fields     *resource.FieldFilter
	Approval   *approval.MemoryEngine
	Quotas     *quotas.MemoryLimiter
	Idempotency *idempotency.MemoryStore
	Guardrails *guardrails.Chain
	DBs        *db.Registry
	AuditSink  *audit.MemorySink
	client     *loom.Client
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
	if cfg.AuditSink != nil {
		sink = &audit.MultiSink{Sinks: []audit.Sink{memSink, cfg.AuditSink}}
	}
	gr := guardrails.DefaultChain()
	// SQL-bearing ops get schema + secrets; database package enforces SQL class.

	rt, err := runtime.New(runtime.Dependencies{
		Registry:       reg,
		Verifier:       ver,
		Boundary:       bnd,
		Policy:         pol,
		Resources:      res,
		Fields:         fields,
		Guardrails:     gr,
		Risk:           risk.NewSimpleEngine(),
		RiskBlock:      &risk.Blocker{MaxAllowed: core.RiskCritical},
		Approval:       apr,
		Quotas:         q,
		Idempotency:    idem,
		Audit:          audit.NewLogger(sink),
		AllowAnonymous: cfg.AllowAnonymous,
	})
	if err != nil {
		return nil, err
	}
	a := &App{
		Runtime:     rt,
		Registry:    reg,
		Verifier:    ver,
		Boundary:    bnd,
		Policy:      pol,
		Resources:   res,
		Fields:      fields,
		Approval:    apr,
		Quotas:      q,
		Idempotency: idem,
		Guardrails:  gr,
		DBs:         db.NewRegistry(),
		AuditSink:   memSink,
		client:      loom.NewClient(rt),
	}
	return a, nil
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
	if err := a.Verifier.Register(identity.StaticPrincipal{
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
	return a.Boundary.Grant(id, b)
}

// AllowPolicy adds an explicit allow rule.
func (a *App) AllowPolicy(rule policy.Rule) error {
	return a.Policy.AddRule(rule)
}

// AllowResource adds a resource ACL rule.
func (a *App) AllowResource(rule resource.Rule) error {
	return a.Resources.Grant(rule)
}

// AllowFields grants output fields.
func (a *App) AllowFields(id core.PrincipalID, b core.BoundaryID, op string, fields []string) error {
	return a.Fields.GrantFields(id, b, op, fields)
}

// IssueApproval issues a single-use approval token (tests/admin tooling).
func (a *App) IssueApproval(token string, principal core.PrincipalID, op string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	return a.Approval.Issue(token, principal, op, boundary, maxRisk, ttl)
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
