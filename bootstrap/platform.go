// Package bootstrap wires a full adversarial platform stack for demos and servers.
package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/loreste/loom/approval"
	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/boundary"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/domains/admin"
	"github.com/loreste/loom/domains/ai"
	"github.com/loreste/loom/domains/deployment"
	"github.com/loreste/loom/domains/document"
	"github.com/loreste/loom/domains/payment"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/guardrails"
	"github.com/loreste/loom/idempotency"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/persist"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/quotas"
	"github.com/loreste/loom/resource"
	"github.com/loreste/loom/risk"
	"github.com/loreste/loom/runtime"
	"github.com/loreste/loom/store/postgres"
)

// Platform is a fully wired Loom deployment.
type Platform struct {
	Runtime     *runtime.Runtime
	Registry    *core.Registry
	Memory      *identity.MemoryVerifier
	JWT         *identity.JWTVerifier
	MTLS        *identity.MTLSVerifier
	Multi       *identity.MultiVerifier
	Delegation  *identity.MemoryDelegation
	Boundary    *boundary.MemoryChecker
	Policy      *policy.MemoryEngine
	Resources   *resource.MemoryChecker
	Fields      *resource.FieldFilter
	Approval    approval.Store
	Quotas      quotas.Limiter
	QuotaConfig *quotas.Config
	Idempotency idempotency.Store
	AuditSink   *audit.MemorySink
	// JWTSecret used for minting demo tokens (dev only).
	JWTSecret []byte
	// DemoTokens contains process-local development credentials generated at
	// startup or explicitly supplied by the caller.
	DemoTokens map[core.PrincipalID]string
	Docs       *document.Store
	DataDir    string
	// DB is set when DatabaseURL is configured.
	DB *sql.DB
	// Redis client when RedisURL is set.
	Redis *redis.Client
	// Ready checks durable deps for HTTP /readyz.
	Ready func(context.Context) error
	// Metrics collects bounded pipeline observations; applications may bridge it
	// to Prometheus or OpenTelemetry through their adapter.
	Metrics *runtime.Metrics
	// PolicySource is set when distributed policy is enabled (file or postgres).
	PolicySource policy.Source
	// PolicySyncer background applier; Stopped on Close.
	PolicySyncer *policy.Syncer
	// jwtIssuer/jwtAudience are the configured JWT iss/aud used by MintDemoJWT.
	jwtIssuer   string
	jwtAudience string
	jwtKeyID    string
	// auditFile is the JSONL audit sink handle (when AuditJSONL/DataDir set); closed by Close.
	auditFile *os.File
}

// Config for platform bootstrap.
type Config struct {
	JWTSecret   []byte
	JWTKeyID    string
	JWTIssuer   string
	JWTAudience string
	// JWTClaimAttributes maps verified JWT claims into Identity.Attributes.
	// It is useful for tenant claims and other policy inputs.
	JWTClaimAttributes map[string]string
	AuditJSONL         string
	// DataDir file stores; ignored when DatabaseURL set.
	DataDir string
	// DatabaseURL Postgres DSN.
	DatabaseURL string
	// RedisURL redis://… for distributed quotas.
	RedisURL string
	// FailClosedQuotas default true when Redis is used.
	FailClosedQuotas *bool
	// PG pool tuning.
	PGMaxOpenConns int
	PGMaxIdleConns int
	// PolicyPath enables file-backed distributed policy (JSON document).
	// When DatabaseURL is set, Postgres policy store is preferred unless PolicyPath is set alone.
	PolicyPath string
	// PolicySyncInterval for multi-node pull (default 5s). 0 = default; <0 disables background sync.
	PolicySyncInterval time.Duration
	// SeedPolicyPublish if true (default), publishes local seed as version 1 when store empty.
	DisableSeedPolicyPublish bool
	// DisableDemoPrincipals skips seeding development bearer principals and their
	// demo policy/resource/field grants. Enable this for shared or production
	// environments; development tokens are generated per process by default.
	DisableDemoPrincipals bool
	// DemoTokens optionally supplies local-development credentials. Omitted
	// principals receive cryptographically random tokens at startup.
	DemoTokens map[string]string
	// RequireDurable marks a production-ish deployment (mirrors
	// config.Config.RequireDurable / LOOM_REQUIRE_DURABLE). When set,
	// NewPlatform refuses to start unless DisableDemoPrincipals is also set.
	RequireDurable bool
	// TenantResolver binds a verified identity tenant claim to each request
	// boundary. Leave nil for applications that do not use tenant claims.
	TenantResolver runtime.TenantResolver
}

// NewPlatform builds deny-by-default stack with demo principals and domain ops.
func NewPlatform(cfg Config) (*Platform, error) {
	secret := cfg.JWTSecret
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generate ephemeral jwt secret: %w", err)
		}
	}
	if len(secret) < 16 {
		return nil, fmt.Errorf("%w: jwt secret too short", core.ErrInvalidArgument)
	}
	failClosed := true
	if cfg.FailClosedQuotas != nil {
		failClosed = *cfg.FailClosedQuotas
	}
	if cfg.RequireDurable && !cfg.DisableDemoPrincipals {
		return nil, fmt.Errorf("%w: RequireDurable set but demo principals enabled (set DisableDemoPrincipals)", core.ErrInvalidArgument)
	}
	if cfg.RequireDurable {
		if cfg.DatabaseURL == "" && cfg.DataDir == "" {
			return nil, fmt.Errorf("%w: RequireDurable requires DatabaseURL or DataDir", core.ErrInvalidArgument)
		}
		if cfg.RedisURL == "" {
			return nil, fmt.Errorf("%w: RequireDurable requires RedisURL for distributed quota state", core.ErrInvalidArgument)
		}
		if len(cfg.JWTSecret) == 0 {
			return nil, fmt.Errorf("%w: RequireDurable requires an injected JWT secret", core.ErrInvalidArgument)
		}
	}

	reg := core.NewRegistry()
	mem := identity.NewMemoryVerifier()
	jwt, err := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets:         map[string][]byte{cfg.JWTKeyID: secret},
		Issuer:          cfg.JWTIssuer,
		Audience:        cfg.JWTAudience,
		ClaimAttributes: cfg.JWTClaimAttributes,
	})
	if err != nil {
		return nil, err
	}
	mtls := identity.NewMTLSVerifier()
	multi := identity.NewMultiVerifier(map[string]identity.Verifier{
		"bearer": mem,
		"jwt":    jwt,
		"mtls":   mtls,
	})
	del := identity.NewMemoryDelegation()
	bnd := boundary.NewMemoryChecker()
	pol := policy.NewMemoryEngine()
	res := resource.NewMemoryChecker()
	fields := resource.NewFieldFilter()
	qcfg := quotas.NewConfig()
	memSink := &audit.MemorySink{}

	var (
		apr            approval.Store
		idem           idempotency.Store
		executionStore execution.Store
		auditPath      = cfg.AuditJSONL
		db             *sql.DB
		rdb            *redis.Client
		readyFns       []func(context.Context) error
		extraSink      audit.Sink
		limiter        quotas.Limiter
		policySrc      policy.Source
		pgBundle       *postgres.Bundle
		auditFile      *os.File
	)

	// Quotas: Redis when configured, else memory. Shared Config for limits.
	if cfg.RedisURL != "" {
		client, err := quotas.OpenClient(cfg.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("redis: %w", err)
		}
		rdb = client
		rl := quotas.NewRedisLimiter(client, qcfg)
		rl.FailClosed = failClosed
		limiter = rl
		readyFns = append(readyFns, func(ctx context.Context) error {
			return client.Ping(ctx).Err()
		})
	} else {
		limiter = quotas.NewMemoryLimiterWithConfig(qcfg)
	}

	// Precedence: DatabaseURL > DataDir > memory.
	if cfg.DatabaseURL != "" {
		pool := postgres.DefaultPool()
		if cfg.PGMaxOpenConns > 0 {
			pool.MaxOpenConns = cfg.PGMaxOpenConns
		}
		if cfg.PGMaxIdleConns > 0 {
			pool.MaxIdleConns = cfg.PGMaxIdleConns
		}
		bundle, err := postgres.NewBundlePool(context.Background(), cfg.DatabaseURL, pool)
		if err != nil {
			if rdb != nil {
				_ = rdb.Close()
			}
			return nil, fmt.Errorf("postgres: %w", err)
		}
		pgBundle = bundle
		db = bundle.DB
		apr = bundle.Approvals
		idem = bundle.Idempotency
		executionStore = bundle.ExecutionStatus
		extraSink = bundle.Audit
		policySrc = bundle.Policy
		readyFns = append(readyFns, func(ctx context.Context) error {
			return postgres.Ready(ctx, db)
		})
	} else if cfg.DataDir != "" {
		if err := persist.EnsureDir(cfg.DataDir); err != nil {
			if rdb != nil {
				_ = rdb.Close()
			}
			return nil, err
		}
		fe, err := approval.NewFileEngine(persist.Path(cfg.DataDir, persist.FileApprovals))
		if err != nil {
			if rdb != nil {
				_ = rdb.Close()
			}
			return nil, fmt.Errorf("approvals store: %w", err)
		}
		apr = fe
		fs, err := idempotency.NewFileStore(persist.Path(cfg.DataDir, persist.FileIdempotency))
		if err != nil {
			if rdb != nil {
				_ = rdb.Close()
			}
			return nil, fmt.Errorf("idempotency store: %w", err)
		}
		idem = fs
		executionStore, err = execution.NewFileStore(persist.Path(cfg.DataDir, persist.FileExecution))
		if err != nil {
			if rdb != nil {
				_ = rdb.Close()
			}
			return nil, fmt.Errorf("execution store: %w", err)
		}
		if auditPath == "" {
			auditPath = persist.Path(cfg.DataDir, persist.FileAuditJSONL)
		}
	} else {
		apr = approval.NewMemoryEngine()
		idem = idempotency.NewMemoryStore()
		executionStore = execution.NewMemoryStore()
	}

	var sinks []audit.Sink
	if !cfg.RequireDurable {
		sinks = append(sinks, memSink)
	}
	if extraSink != nil {
		sinks = append(sinks, extraSink)
	}
	if auditPath != "" {
		if err := os.MkdirAll(parentDir(auditPath), 0o700); err != nil {
			_ = closeAll(db, rdb)
			return nil, err
		}
		// #nosec G304 -- auditPath is explicit application configuration.
		f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			_ = closeAll(db, rdb)
			return nil, err
		}
		auditFile = f
		sinks = append(sinks, audit.NewDurableWriterSink(f))
	}
	var auditLogger *audit.Logger
	if len(sinks) == 1 {
		auditLogger = audit.NewLogger(memSink)
	} else {
		auditLogger = audit.NewLogger(&audit.MultiSink{Sinks: sinks})
	}

	gr := guardrails.DefaultChain()
	gr.Add(&guardrails.FinancialGuard{MaxAmount: core.Money{Units: 10_000, Currency: "USD"}})
	metrics := runtime.NewMetrics()
	mode := runtime.ModeDevelopment
	if cfg.RequireDurable {
		mode = runtime.ModeProduction
	}
	var recovery idempotency.RecoveryQueue
	if q, ok := executionStore.(idempotency.RecoveryQueue); ok {
		recovery = q
	} else if q, ok := idem.(idempotency.RecoveryQueue); ok {
		recovery = q
	}

	rt, err := runtime.New(runtime.Dependencies{
		Mode:                mode,
		Registry:            reg,
		Verifier:            multi,
		Delegation:          del,
		Boundary:            bnd,
		Policy:              pol,
		Resources:           res,
		Fields:              fields,
		Guardrails:          gr,
		Risk:                risk.NewSimpleEngine(),
		RiskBlock:           &risk.Blocker{MaxAllowed: core.RiskCritical},
		Approval:            apr,
		Quotas:              limiter,
		Idempotency:         idem,
		ExecutionStatus:     executionStore,
		IdempotencyRecovery: recovery,
		Audit:               auditLogger,
		Observer:            metrics,
		Tenant:              cfg.TenantResolver,
	})
	if err != nil {
		if auditFile != nil {
			_ = auditFile.Close()
		}
		_ = closeAll(db, rdb)
		return nil, err
	}

	ready := func(ctx context.Context) error {
		for _, fn := range readyFns {
			if err := fn(ctx); err != nil {
				return err
			}
		}
		return nil
	}
	if len(readyFns) == 0 {
		ready = nil
	}

	p := &Platform{
		Runtime:     rt,
		Registry:    reg,
		Memory:      mem,
		JWT:         jwt,
		MTLS:        mtls,
		Multi:       multi,
		Delegation:  del,
		Boundary:    bnd,
		Policy:      pol,
		Resources:   res,
		Fields:      fields,
		Approval:    apr,
		Quotas:      limiter,
		QuotaConfig: qcfg,
		Idempotency: idem,
		AuditSink:   memSink,
		JWTSecret:   secret,
		DemoTokens:  make(map[core.PrincipalID]string),
		Docs:        document.NewStore(),
		DataDir:     cfg.DataDir,
		DB:          db,
		Redis:       rdb,
		Ready:       ready,
		Metrics:     metrics,
		jwtIssuer:   cfg.JWTIssuer,
		jwtAudience: cfg.JWTAudience,
		jwtKeyID:    cfg.JWTKeyID,
		auditFile:   auditFile,
	}
	// Policy source: explicit file path overrides; else postgres when available;
	// else DataDir/policy.json when data dir set.
	if cfg.PolicyPath != "" {
		policySrc = policy.NewFileSource(cfg.PolicyPath)
	} else if policySrc == nil && cfg.DataDir != "" {
		policySrc = policy.NewFileSource(persist.Path(cfg.DataDir, "policy.json"))
	}
	_ = pgBundle

	if err := p.registerDomains(); err != nil {
		_ = p.Close()
		return nil, err
	}
	// Register policy admin ops when source exists
	if policySrc != nil {
		p.PolicySource = policySrc
		if err := admin.RegisterPolicy(p.Registry, admin.PolicyDeps{
			Source: policySrc,
			Engine: p.Policy,
			OnPublish: func(doc *policy.Document) {
				_ = doc
				if p.PolicySyncer != nil {
					_ = p.PolicySyncer.SyncOnce(context.Background())
				}
			},
		}); err != nil {
			_ = p.Close()
			return nil, err
		}
	}
	if !cfg.DisableDemoPrincipals {
		if err := p.seedDemoPrincipals(cfg.DemoTokens); err != nil {
			_ = p.Close()
			return nil, err
		}
	}
	if err := p.startPolicySync(cfg, policySrc); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

func (p *Platform) startPolicySync(cfg Config, src policy.Source) error {
	if src == nil {
		return nil
	}
	p.PolicySource = src
	// Seed publish: first node writes demo rules as v1 when store empty.
	if !cfg.DisableSeedPolicyPublish {
		_, err := src.Load(context.Background())
		if errors.Is(err, core.ErrNotFound) {
			doc := &policy.Document{
				Version: 1,
				ID:      "default",
				Rules:   p.Policy.Snapshot(),
			}
			if pubErr := src.Publish(context.Background(), doc); pubErr != nil && !errors.Is(pubErr, core.ErrAlreadyExists) {
				return fmt.Errorf("seed policy publish: %w", pubErr)
			}
		} else if err != nil {
			return fmt.Errorf("policy load: %w", err)
		}
	}
	if cfg.PolicySyncInterval < 0 {
		// one-shot only
		syncer := policy.NewSyncer(src, p.Policy, time.Hour)
		return syncer.SyncOnce(context.Background())
	}
	interval := cfg.PolicySyncInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	syncer := policy.NewSyncer(src, p.Policy, interval)
	syncer.Logger = log.Default()
	if err := syncer.SyncOnce(context.Background()); err != nil {
		return err
	}
	syncer.Start(context.Background())
	p.PolicySyncer = syncer
	return nil
}

func closeAll(db *sql.DB, rdb *redis.Client) error {
	var first error
	if rdb != nil {
		if err := rdb.Close(); err != nil && first == nil {
			first = err
		}
	}
	if db != nil {
		if err := db.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			if i == 0 {
				return string(path[0])
			}
			return path[:i]
		}
	}
	return "."
}

func (p *Platform) registerDomains() error {
	if err := document.Register(p.Registry, p.Docs); err != nil {
		return err
	}
	if err := payment.Register(p.Registry); err != nil {
		return err
	}
	if err := deployment.Register(p.Registry); err != nil {
		return err
	}
	if err := ai.Register(p.Registry); err != nil {
		return err
	}
	return admin.Register(p.Registry, admin.Deps{
		Approvals: p.Approval,
		Registry:  p.Registry,
	})
}

func (p *Platform) demoToken(configured map[string]string, id core.PrincipalID) (string, error) {
	if token := configured[string(id)]; token != "" {
		p.DemoTokens[id] = token
		return token, nil
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate demo token for %s: %w", id, err)
	}
	token := "loom-dev-" + hex.EncodeToString(raw)
	p.DemoTokens[id] = token
	return token, nil
}

// DemoToken returns a generated or configured development token. It is
// intentionally unavailable when demo principals are disabled.
func (p *Platform) DemoToken(id core.PrincipalID) string {
	if p == nil {
		return ""
	}
	return p.DemoTokens[id]
}

func (p *Platform) seedDemoPrincipals(configured map[string]string) error {
	aliceToken, err := p.demoToken(configured, "user:alice")
	if err != nil {
		return err
	}
	bobToken, err := p.demoToken(configured, "user:bob")
	if err != nil {
		return err
	}
	opsToken, err := p.demoToken(configured, "user:ops")
	if err != nil {
		return err
	}
	approverToken, err := p.demoToken(configured, "user:approver")
	if err != nil {
		return err
	}
	agentToken, err := p.demoToken(configured, "agent:assistant")
	if err != nil {
		return err
	}
	if err := p.Memory.Register(identity.StaticPrincipal{
		ID: "user:alice", Type: "user", Boundary: "dev", Token: aliceToken,
		// catalog.spec lets agents discover callable tools for this principal.
		Capabilities: []string{"document.read", "document.write", "ai.complete", "catalog.spec"},
	}); err != nil {
		return err
	}
	if err := p.Memory.Register(identity.StaticPrincipal{
		ID: "user:bob", Type: "user", Boundary: "dev", Token: bobToken,
		Capabilities: []string{"payment.capture", "payment.refund", "document.read", "catalog.spec"},
	}); err != nil {
		return err
	}
	if err := p.Memory.Register(identity.StaticPrincipal{
		ID: "user:ops", Type: "user", Boundary: "staging", Token: opsToken,
		Capabilities: []string{"deployment.release", "server.restart", "document.read", "catalog.spec"},
	}); err != nil {
		return err
	}
	if err := p.Memory.Register(identity.StaticPrincipal{
		ID: "user:approver", Type: "user", Boundary: "dev", Token: approverToken,
		Capabilities: []string{
			"approval.issue", "catalog.list", "catalog.spec", "document.read",
			"policy.publish", "policy.get",
		},
	}); err != nil {
		return err
	}
	if err := p.Memory.Register(identity.StaticPrincipal{
		ID: "agent:assistant", Type: "agent", Boundary: "dev", Token: agentToken,
		Capabilities: []string{"ai.complete", "ai.tool_call", "document.read", "catalog.spec"},
	}); err != nil {
		return err
	}
	if err := p.MTLS.Register(identity.CertPrincipal{
		FingerprintSHA256: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		ID:                "svc:payments",
		Type:              "service",
		Boundary:          "dev",
		Capabilities:      []string{"payment.capture"},
	}); err != nil {
		return err
	}

	for _, pair := range []struct {
		p core.PrincipalID
		b core.BoundaryID
	}{
		{"user:alice", "dev"},
		{"user:bob", "dev"},
		{"user:ops", "staging"},
		{"user:ops", "dev"},
		{"user:approver", "dev"},
		{"user:approver", "staging"},
		{"agent:assistant", "dev"},
		{"svc:payments", "dev"},
	} {
		if err := p.Boundary.Grant(pair.p, pair.b); err != nil {
			return err
		}
	}

	rules := []policy.Rule{
		{Principal: "user:alice", Boundary: "dev", Operation: "document.read", Priority: 10},
		{Principal: "user:alice", Boundary: "dev", Operation: "document.write", Priority: 10},
		{Principal: "user:alice", Boundary: "dev", Operation: "ai.complete", Priority: 10},
		{Principal: "user:alice", Boundary: "dev", Operation: "catalog.spec", Priority: 10},
		{Principal: "user:bob", Boundary: "dev", Operation: "payment.capture", Priority: 10},
		{Principal: "user:bob", Boundary: "dev", Operation: "payment.refund", Priority: 10},
		{Principal: "user:bob", Boundary: "dev", Operation: "document.read", Priority: 5},
		{Principal: "user:bob", Boundary: "dev", Operation: "catalog.spec", Priority: 10},
		{Principal: "user:ops", Boundary: "staging", Operation: "deployment.release", Priority: 10},
		{Principal: "user:ops", Boundary: "staging", Operation: "server.restart", Priority: 10},
		{Principal: "user:ops", Boundary: "dev", Operation: "document.read", Priority: 5},
		{Principal: "user:ops", Boundary: "dev", Operation: "catalog.spec", Priority: 10},
		{Principal: "user:ops", Boundary: "staging", Operation: "catalog.spec", Priority: 10},
		{Principal: "user:ops", Operation: "server.destroy", Deny: true, Priority: 100},
		{Principal: "user:approver", Boundary: "dev", Operation: "approval.issue", Priority: 20},
		{Principal: "user:approver", Boundary: "staging", Operation: "approval.issue", Priority: 20},
		{Principal: "user:approver", Boundary: "dev", Operation: "catalog.list", Priority: 10},
		{Principal: "user:approver", Boundary: "dev", Operation: "catalog.spec", Priority: 10},
		{Principal: "user:approver", Boundary: "dev", Operation: "document.read", Priority: 5},
		{Principal: "user:approver", Boundary: "dev", Operation: "policy.publish", Priority: 20},
		{Principal: "user:approver", Boundary: "dev", Operation: "policy.get", Priority: 10},
		{Principal: "user:alice", Operation: "approval.issue", Deny: true, Priority: 100},
		{Principal: "user:bob", Operation: "approval.issue", Deny: true, Priority: 100},
		{Principal: "agent:assistant", Boundary: "dev", Operation: "ai.complete", Priority: 10},
		{Principal: "agent:assistant", Boundary: "dev", Operation: "ai.tool_call", Priority: 10},
		{Principal: "agent:assistant", Boundary: "dev", Operation: "document.read", Priority: 5},
		{Principal: "agent:assistant", Boundary: "dev", Operation: "catalog.spec", Priority: 10},
		{Principal: "svc:payments", Boundary: "dev", Operation: "payment.capture", Priority: 10},
	}
	for _, r := range rules {
		if err := p.Policy.AddRule(r); err != nil {
			return err
		}
	}

	resRules := []resource.Rule{
		{Principal: "user:alice", Boundary: "dev", Type: "document", ID: "*", Operations: []string{"document.read", "document.write"}},
		{Principal: "user:bob", Boundary: "dev", Type: "document", ID: "*", Operations: []string{"document.read"}},
		{Principal: "user:bob", Boundary: "dev", Type: "payment", ID: "*", Operations: []string{"payment.capture", "payment.refund"}},
		{Principal: "user:ops", Boundary: "staging", Type: "service", ID: "*", Operations: []string{"deployment.release"}},
		{Principal: "user:ops", Boundary: "staging", Type: "server", ID: "*", Operations: []string{"server.restart"}},
		{Principal: "user:ops", Boundary: "dev", Type: "document", ID: "*", Operations: []string{"document.read"}},
		{Principal: "user:approver", Boundary: "dev", Type: "document", ID: "*", Operations: []string{"document.read"}},
		{Principal: "agent:assistant", Boundary: "dev", Type: "document", ID: "*", Operations: []string{"document.read"}},
		{Principal: "svc:payments", Boundary: "dev", Type: "payment", ID: "*", Operations: []string{"payment.capture"}},
	}
	for _, r := range resRules {
		if err := p.Resources.Grant(r); err != nil {
			return err
		}
	}

	fieldGrants := []struct {
		id     core.PrincipalID
		b      core.BoundaryID
		op     string
		fields []string
	}{
		{"user:alice", "dev", "document.read", []string{"id", "title", "body", "status"}},
		{"user:alice", "dev", "document.write", []string{"id", "title", "status"}},
		{"user:alice", "dev", "ai.complete", []string{"completion_id", "text", "echo_preview"}},
		{"user:alice", "dev", "catalog.spec", []string{"tools", "count"}},
		{"user:bob", "dev", "payment.capture", []string{"payment_id", "status", "amount", "currency", "merchant_id"}},
		{"user:bob", "dev", "payment.refund", []string{"refund_id", "payment_id", "status", "amount"}},
		{"user:bob", "dev", "document.read", []string{"id", "title"}},
		{"user:bob", "dev", "catalog.spec", []string{"tools", "count"}},
		{"user:ops", "staging", "deployment.release", []string{"*"}},
		{"user:ops", "staging", "server.restart", []string{"*"}},
		{"user:ops", "dev", "document.read", []string{"id", "title"}},
		{"user:ops", "dev", "catalog.spec", []string{"tools", "count"}},
		{"user:ops", "staging", "catalog.spec", []string{"tools", "count"}},
		{"user:approver", "dev", "approval.issue", []string{"status", "token", "principal", "operation", "boundary", "ttl_seconds", "max_risk", "issued_by"}},
		{"user:approver", "staging", "approval.issue", []string{"status", "token", "principal", "operation", "boundary", "ttl_seconds", "max_risk", "issued_by"}},
		{"user:approver", "dev", "catalog.list", []string{"operations", "count"}},
		{"user:approver", "dev", "catalog.spec", []string{"tools", "count"}},
		{"user:approver", "dev", "document.read", []string{"id", "title"}},
		{"user:approver", "dev", "policy.publish", []string{"status", "version", "id", "rule_count", "published_by"}},
		{"user:approver", "dev", "policy.get", []string{"id", "version", "rule_count", "rules", "updated_at"}},
		{"agent:assistant", "dev", "ai.complete", []string{"completion_id", "text", "echo_preview"}},
		{"agent:assistant", "dev", "ai.tool_call", []string{"tool_call_id", "tool", "status"}},
		{"agent:assistant", "dev", "document.read", []string{"id", "title", "body"}},
		{"agent:assistant", "dev", "catalog.spec", []string{"tools", "count"}},
		{"svc:payments", "dev", "payment.capture", []string{"payment_id", "status", "amount", "currency", "merchant_id"}},
	}
	for _, g := range fieldGrants {
		if err := p.Fields.GrantFields(g.id, g.b, g.op, g.fields); err != nil {
			return err
		}
	}

	// Quotas via shared config (works for memory + redis)
	_ = p.QuotaConfig.SetLimit("agent:assistant", "dev", "ai.complete", 30, time.Minute)
	_ = p.QuotaConfig.SetLimit("agent:assistant", "dev", "ai.tool_call", 20, time.Minute)
	_ = p.QuotaConfig.SetLimit("user:bob", "dev", "payment.capture", 50, time.Minute)
	_ = p.QuotaConfig.SetLimit("user:approver", "dev", "approval.issue", 100, time.Minute)

	return nil
}

// MintDemoJWT issues a short-lived JWT for a principal (dev tooling).
func (p *Platform) MintDemoJWT(sub core.PrincipalID, boundary core.BoundaryID, caps []string, typ string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if typ == "" {
		typ = "user"
	}
	now := time.Now()
	iss, aud := p.jwtIssuer, p.jwtAudience
	claims := map[string]any{
		"sub":          string(sub),
		"exp":          now.Add(ttl).Unix(),
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"boundary":     string(boundary),
		"typ":          typ,
		"capabilities": caps,
	}
	if iss != "" {
		claims["iss"] = iss
	}
	if aud != "" {
		claims["aud"] = aud
	}
	return identity.MintHS256(p.JWTSecret, p.jwtKeyID, claims)
}

// IssueApproval is a convenience for demos/tests (bypasses governed op — test only).
func (p *Platform) IssueApproval(token string, principal core.PrincipalID, op string, boundary core.BoundaryID, maxRisk core.RiskLevel, ttl time.Duration) error {
	return p.Approval.Issue(token, principal, op, boundary, maxRisk, ttl)
}

// RegisterMTLSPrincipal adds a client cert mapping (tests / ops bootstrap).
func (p *Platform) RegisterMTLSPrincipal(fp string, id core.PrincipalID, boundary core.BoundaryID, caps []string) error {
	if err := p.MTLS.Register(identity.CertPrincipal{
		FingerprintSHA256: fp,
		ID:                id,
		Type:              "service",
		Boundary:          boundary,
		Capabilities:      caps,
	}); err != nil {
		return err
	}
	return p.Boundary.Grant(id, boundary)
}

// Close releases durable resources (Postgres + Redis + policy sync + audit file).
func (p *Platform) Close() error {
	if p == nil {
		return nil
	}
	if p.PolicySyncer != nil {
		p.PolicySyncer.Stop()
		p.PolicySyncer = nil
	}
	var first error
	if p.auditFile != nil {
		if err := p.auditFile.Close(); err != nil {
			first = err
		}
		p.auditFile = nil
	}
	if err := closeAll(p.DB, p.Redis); err != nil && first == nil {
		first = err
	}
	return first
}
