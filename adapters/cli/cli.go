// Package cli is a thin adapter: argv/env → core.Request → Runtime.Execute.
// It cannot bypass enforcement.
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/config"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

// Adapter wraps a runtime for CLI use.
type Adapter struct {
	RT       *runtime.Runtime
	Platform *bootstrap.Platform
	// PlatformFactory rebuilds platform with serve flags (data-dir, etc.).
	PlatformFactory func(bootstrap.Config) (*bootstrap.Platform, error)
	TokenEnv        string
	Out             io.Writer
	Err             io.Writer
}

// New creates a CLI adapter.
func New(rt *runtime.Runtime) *Adapter {
	return &Adapter{
		RT:       rt,
		TokenEnv: "LOOM_TOKEN",
		Out:      os.Stdout,
		Err:      os.Stderr,
	}
}

// NewWithPlatform enables serve/mint/approve commands.
func NewWithPlatform(p *bootstrap.Platform) *Adapter {
	a := New(p.Runtime)
	a.Platform = p
	a.PlatformFactory = bootstrap.NewPlatform
	return a
}

// Run parses args and dispatches commands.
func (a *Adapter) Run(ctx context.Context, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(a.errW(), `usage:
  loom exec <operation> [flags]
  loom serve [--addr=:8080] [--data-dir=./data] [--database-url=postgres://...] [--redis-url=redis://...] [--tls-cert=] [--tls-key=] [--client-ca=]
  loom mint-jwt --sub=user:alice --boundary=dev --caps=document.read
  loom approve --token=appr-1 --principal=user:bob --op=payment.capture --boundary=dev
  loom version`)
		return 2
	}
	switch args[0] {
	case "exec":
		return a.runExec(ctx, args[1:])
	case "serve":
		return a.runServe(ctx, args[1:])
	case "mint-jwt":
		return a.runMintJWT(args[1:])
	case "approve":
		return a.runApprove(args[1:])
	case "version":
		fmt.Fprintln(a.outW(), "loom 0.2.1-phase2")
		return 0
	case "help", "-h", "--help":
		return a.Run(ctx, nil)
	default:
		fmt.Fprintln(a.errW(), "unknown command:", args[0])
		return 2
	}
}

func (a *Adapter) runExec(ctx context.Context, args []string) int {
	if a == nil || a.RT == nil {
		fmt.Fprintln(a.errW(), "loom: runtime not configured")
		return 2
	}
	if len(args) < 1 {
		fmt.Fprintln(a.errW(), "operation required")
		return 2
	}
	op := args[0]
	flags := parseFlags(args[1:])

	token := os.Getenv(a.TokenEnv)
	if flags["token"] != "" {
		token = flags["token"]
	}

	var input map[string]any
	if raw := flags["input"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			fmt.Fprintln(a.errW(), "invalid --input json:", err)
			return 2
		}
	}
	if input == nil {
		input = map[string]any{}
	}

	var res *core.ResourceRef
	if flags["resource-type"] != "" || flags["resource-id"] != "" {
		res = &core.ResourceRef{
			Type: flags["resource-type"],
			ID:   flags["resource-id"],
		}
	}

	var fields []string
	if flags["field"] != "" {
		fields = strings.Split(flags["field"], ",")
	}

	approvalTok := flags["approval"]
	if issue := flags["issue-approval"]; issue != "" && a.Platform != nil {
		principal := flags["principal"]
		if principal == "" {
			fmt.Fprintln(a.errW(), "--issue-approval requires --principal=")
			return 2
		}
		if err := a.Platform.IssueApproval(issue, core.PrincipalID(principal), op, core.BoundaryID(flags["boundary"]), core.RiskCritical, time.Hour); err != nil {
			fmt.Fprintln(a.errW(), "issue-approval:", err)
			return 2
		}
		approvalTok = issue
	}

	req := core.Request{
		Operation: op,
		Credentials: core.Credentials{
			Scheme: "bearer",
			Token:  token,
		},
		Boundary:       core.BoundaryID(flags["boundary"]),
		Resource:       res,
		Input:          input,
		Fields:         fields,
		IdempotencyKey: flags["idempotency-key"],
		ApprovalToken:  approvalTok,
		Metadata: map[string]string{
			"adapter": "cli",
		},
	}

	resp := a.RT.Execute(ctx, req)
	enc := json.NewEncoder(a.outW())
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		fmt.Fprintln(a.errW(), err)
		return 1
	}
	if !resp.Allowed {
		return 1
	}
	return 0
}

func (a *Adapter) runServe(ctx context.Context, args []string) int {
	flags := parseFlags(args)
	addr := flags["addr"]
	if addr == "" {
		addr = ":8080"
	}
	dataDir := flags["data-dir"]
	if dataDir == "" {
		dataDir = os.Getenv("LOOM_DATA_DIR")
	}
	dbURL := flags["database-url"]
	if dbURL == "" {
		dbURL = os.Getenv("LOOM_DATABASE_URL")
	}
	redisURL := flags["redis-url"]
	if redisURL == "" {
		redisURL = os.Getenv("LOOM_REDIS_URL")
	}

	// Rebuild platform with durable backends when factory available.
	rt := a.RT
	var readyFn func(context.Context) error
	if a.PlatformFactory != nil && (dataDir != "" || dbURL != "" || redisURL != "") {
		fc := true
		envCfg := config.Load()
		p, err := a.PlatformFactory(bootstrap.Config{
			DataDir:          dataDir,
			DatabaseURL:      dbURL,
			RedisURL:         redisURL,
			FailClosedQuotas: &fc,
			RequireDurable:        envCfg.RequireDurable,
			DisableDemoPrincipals: envCfg.DisableDemoPrincipals,
		})
		if err != nil {
			fmt.Fprintln(a.errW(), "bootstrap:", err)
			return 2
		}
		a.Platform = p
		rt = p.Runtime
		readyFn = p.Ready
		if dbURL != "" {
			fmt.Fprintln(a.errW(), "loom storage: postgres (approvals/idempotency/audit)")
		} else if dataDir != "" {
			fmt.Fprintf(a.errW(), "loom data dir: %s (approvals/idempotency/audit persisted)\n", dataDir)
		}
		if redisURL != "" {
			fmt.Fprintln(a.errW(), "loom quotas: redis (fail-closed)")
		}
	} else if a.Platform == nil && rt == nil {
		fmt.Fprintln(a.errW(), "loom: runtime not configured")
		return 2
	} else if a.Platform != nil {
		readyFn = a.Platform.Ready
	}

	cfg := loomhttp.ServerConfig{Addr: addr, Ready: readyFn}
	certFile := flags["tls-cert"]
	keyFile := flags["tls-key"]
	clientCA := flags["client-ca"]
	requireMTLS := flags["require-mtls"] == "true" || clientCA != ""

	if certFile != "" || keyFile != "" || clientCA != "" {
		tlsCfg, err := loadServerTLS(certFile, keyFile, clientCA, requireMTLS)
		if err != nil {
			fmt.Fprintln(a.errW(), "tls:", err)
			return 2
		}
		cfg.TLSConfig = tlsCfg
		cfg.RequireMTLS = requireMTLS
	}

	// Wire agent surfaces when platform components are available.
	if a.Platform != nil {
		cfg.Registry = a.Platform.Registry
		cfg.Verifier = a.Platform.Multi
		cfg.MCP = &mcp.Server{
			Adapter:  mcp.New(rt),
			Registry: a.Platform.Registry,
			Verifier: a.Platform.Multi,
		}
	}

	srv, err := loomhttp.NewServer(rt, cfg)
	if err != nil {
		fmt.Fprintln(a.errW(), err)
		return 2
	}

	mode := "http"
	if cfg.TLSConfig != nil {
		mode = "https"
		if requireMTLS {
			mode = "https+mtls"
		}
	}
	extra := ""
	if cfg.MCP != nil {
		extra += " POST /mcp"
	}
	if cfg.Registry != nil {
		extra += " GET /v1/openapi.json"
	}
	fmt.Fprintf(a.errW(), "loom listening on %s (%s) POST /v1/execute%s\n", addr, mode, extra)

	errCh := make(chan error, 1)
	go func() {
		if certFile != "" && keyFile != "" {
			errCh <- srv.ListenAndServeTLS(certFile, keyFile)
		} else if cfg.TLSConfig != nil {
			// TLS config without files (tests inject certs) — use ListenAndServe with TLSConfig set
			errCh <- srv.ListenAndServe()
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-sigCtx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		fmt.Fprintln(a.errW(), "shutdown complete")
		return 0
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(a.errW(), err)
			return 1
		}
		return 0
	}
}

func loadServerTLS(certFile, keyFile, clientCA string, requireMTLS bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if clientCA != "" {
		pem, err := os.ReadFile(clientCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certs in client CA file")
		}
		cfg.ClientCAs = pool
		if requireMTLS {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return cfg, nil
}

func (a *Adapter) runMintJWT(args []string) int {
	if a.Platform == nil {
		fmt.Fprintln(a.errW(), "mint-jwt requires platform bootstrap")
		return 2
	}
	flags := parseFlags(args)
	sub := flags["sub"]
	if sub == "" {
		fmt.Fprintln(a.errW(), "--sub required")
		return 2
	}
	boundary := flags["boundary"]
	var caps []string
	if flags["caps"] != "" {
		caps = strings.Split(flags["caps"], ",")
	}
	ttl := time.Hour
	if flags["ttl"] != "" {
		d, err := time.ParseDuration(flags["ttl"])
		if err != nil {
			fmt.Fprintln(a.errW(), "invalid --ttl")
			return 2
		}
		ttl = d
	}
	tok, err := a.Platform.MintDemoJWT(core.PrincipalID(sub), core.BoundaryID(boundary), caps, flags["typ"], ttl)
	if err != nil {
		fmt.Fprintln(a.errW(), err)
		return 1
	}
	fmt.Fprintln(a.outW(), tok)
	return 0
}

func (a *Adapter) runApprove(args []string) int {
	if a.Platform == nil {
		fmt.Fprintln(a.errW(), "approve requires platform bootstrap")
		return 2
	}
	flags := parseFlags(args)
	token := flags["token"]
	principal := flags["principal"]
	op := flags["op"]
	boundary := flags["boundary"]
	if token == "" || principal == "" || op == "" {
		fmt.Fprintln(a.errW(), "--token --principal --op required")
		return 2
	}
	ttl := time.Hour
	if flags["ttl"] != "" {
		d, err := time.ParseDuration(flags["ttl"])
		if err != nil {
			fmt.Fprintln(a.errW(), "invalid --ttl")
			return 2
		}
		ttl = d
	}
	if err := a.Platform.IssueApproval(token, core.PrincipalID(principal), op, core.BoundaryID(boundary), core.RiskCritical, ttl); err != nil {
		fmt.Fprintln(a.errW(), err)
		return 1
	}
	fmt.Fprintln(a.outW(), `{"status":"issued"}`)
	return 0
}

func (a *Adapter) outW() io.Writer {
	if a.Out != nil {
		return a.Out
	}
	return os.Stdout
}

func (a *Adapter) errW() io.Writer {
	if a.Err != nil {
		return a.Err
	}
	return os.Stderr
}

func parseFlags(args []string) map[string]string {
	out := map[string]string{}
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			continue
		}
		a = strings.TrimPrefix(a, "--")
		if k, v, ok := strings.Cut(a, "="); ok {
			out[k] = v
		} else {
			out[a] = "true"
		}
	}
	return out
}
