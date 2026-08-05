// Package http adapts HTTP to Loom. It never bypasses the runtime.
package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	loomgql "github.com/loreste/loom/adapters/graphql"
	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/catalog"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/runtime"
)

const (
	defaultMaxBody = 1 << 20 // 1 MiB
	defaultReadTO  = 10 * time.Second
	defaultWriteTO = 30 * time.Second
	defaultIdleTO  = 60 * time.Second
)

// ServerConfig tunes the HTTP edge.
type ServerConfig struct {
	Addr         string
	MaxBodyBytes int64
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// RequireMTLS demands a verified client cert (tls.RequestClientCert+Verify).
	RequireMTLS bool
	// TLSConfig optional; when set, ListenAndServeTLS uses it.
	TLSConfig *tls.Config
	// RequireTLS refuses a plaintext ListenAndServe call. Direct production
	// listeners should use ListenAndServeTLS; proxy termination must be an
	// explicit deployment decision outside this adapter.
	RequireTLS bool
	// Logger optional.
	Logger *log.Logger
	// Ready probes whether backend deps are ready (optional).
	Ready func(context.Context) error
	// MCP optional JSON-RPC tools/* server. When set, POST /mcp is registered.
	// Never grants privilege — every tools/call still hits Runtime.Execute.
	MCP *mcp.Server
	// EnableGraphQL registers POST /graphql (mutation execute → Runtime.Execute).
	EnableGraphQL bool
	// OpenAPI enables GET /v1/openapi.json (capability-filtered). Requires
	// Registry + Verifier; when either is nil the route is omitted.
	Registry *core.Registry
	Verifier identity.Verifier
	// RateLimit optional per-IP edge limiter (before auth). Zero = disabled.
	RateLimit RateLimitConfig
	// Metrics exposes GET /metrics when configured. The collector is optional
	// so embedding applications can choose their own telemetry bridge.
	Metrics *runtime.Metrics
	// MetricsAuth authorizes access to /metrics. When nil, metrics are denied
	// unless MetricsPublic is explicitly true.
	MetricsAuth func(*http.Request) bool
	// MetricsPublic explicitly permits unauthenticated metrics exposure.
	MetricsPublic bool
}

// Server is the hardened HTTP adapter.
type Server struct {
	RT     *runtime.Runtime
	Config ServerConfig
	mux    *http.ServeMux
	http   *http.Server
	// gql is non-nil when GraphQL is enabled and successfully constructed.
	gql http.Handler
	rl  *rateLimiter
}

// NewServer builds routes. RT required.
func NewServer(rt *runtime.Runtime, cfg ServerConfig) (*Server, error) {
	if rt == nil {
		return nil, fmt.Errorf("%w: runtime required", core.ErrInvalidArgument)
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBody
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = defaultReadTO
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaultWriteTO
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTO
	}
	s := &Server{RT: rt, Config: cfg, mux: http.NewServeMux(), rl: newRateLimiter(cfg.RateLimit)}
	if cfg.EnableGraphQL {
		requireMTLS := cfg.RequireMTLS
		h, err := loomgql.HandlerWithConfig(rt, loomgql.HandlerConfig{
			MaxBodyBytes: cfg.MaxBodyBytes,
			// Introspection off by default (recon surface).
			ExtractCredentials: func(r *http.Request) (core.Credentials, error) {
				return ExtractCredentials(r, requireMTLS)
			},
		})
		if err != nil {
			return nil, fmt.Errorf("graphql: %w", err)
		}
		s.gql = h
	}
	s.routes()
	s.http = &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.middleware(s.mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 14, // 16 KiB
		TLSConfig:         cfg.TLSConfig,
	}
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	s.mux.HandleFunc("GET /.well-known/loom.json", s.handleManifest)
	s.mux.HandleFunc("POST /v1/execute", s.handleExecute)
	// Convenience aliases — still full Runtime.Execute (no privilege shortcut).
	s.mux.HandleFunc("POST /v1/approvals", s.handleApprovalIssue)
	s.mux.HandleFunc("POST /v1/catalog", s.handleCatalogList)
	s.mux.HandleFunc("GET /v1/execute", methodNotAllowed)
	if s.Config.MCP != nil {
		s.mux.HandleFunc("POST /mcp", s.handleMCP)
		s.mux.HandleFunc("GET /mcp", methodNotAllowed)
	}
	if s.gql != nil {
		s.mux.Handle("POST /graphql", s.gql)
		s.mux.HandleFunc("GET /graphql", methodNotAllowed)
	}
	if s.Config.Registry != nil && s.Config.Verifier != nil {
		s.mux.HandleFunc("GET /v1/openapi.json", s.handleOpenAPI)
	}
	if s.Config.Metrics != nil {
		s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	}
	s.mux.HandleFunc("/", s.handleNotFound)
}

// handleApprovalIssue maps to operation approval.issue through the runtime.
func (s *Server) handleApprovalIssue(w http.ResponseWriter, r *http.Request) {
	s.proxyOperation(w, r, "approval.issue")
}

// handleCatalogList maps to operation catalog.list through the runtime.
func (s *Server) handleCatalogList(w http.ResponseWriter, r *http.Request) {
	s.proxyOperation(w, r, "catalog.list")
}

// proxyOperation forces Operation name; body may omit operation field.
func (s *Server) proxyOperation(w http.ResponseWriter, r *http.Request, op string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.Config.MaxBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	if int64(len(body)) > s.Config.MaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
		return
	}
	var eb executeBody
	if len(body) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&eb); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
	}
	// Force operation — client cannot override via body for these aliases.
	eb.Operation = op
	creds, err := s.extractCredentials(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "credentials"})
		return
	}
	md := eb.Metadata
	if md == nil {
		md = map[string]string{}
	}
	md["adapter"] = "http"
	md["remote_addr"] = stripPort(r.RemoteAddr)
	applyHostileHeaders(md, r)
	idem := eb.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	req := core.Request{
		Operation:        op,
		OperationVersion: eb.OperationVersion,
		Credentials:      creds,
		Boundary:         core.BoundaryID(eb.Boundary),
		Resource:         eb.Resource,
		Input:            eb.Input,
		Fields:           eb.Fields,
		IdempotencyKey:   idem,
		ApprovalToken:    eb.ApprovalToken,
		Metadata:         md,
		TraceID:          r.Header.Get("X-Trace-Id"),
	}
	if req.Input == nil {
		req.Input = map[string]any{}
	}
	writeExecuteResponse(w, s.RT.Execute(r.Context(), req))
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		out := map[string]string{
			"service":  "loom",
			"docs":     "POST /v1/execute",
			"manifest": "/.well-known/loom.json",
		}
		if s.Config.MCP != nil {
			out["mcp"] = "POST /mcp"
		}
		if s.gql != nil {
			out["graphql"] = "POST /graphql"
		}
		if s.Config.Registry != nil && s.Config.Verifier != nil {
			out["openapi"] = "GET /v1/openapi.json"
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

// handleManifest serves the static discovery document. Unauthenticated by
// design: it contains no operation names and no per-caller data.
func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	m := catalog.DefaultManifest("loom")
	if s.Config.MCP == nil {
		m.MCPEndpoint = ""
	}
	if s.gql == nil {
		m.GraphQLEndpoint = ""
	}
	if s.Config.Registry == nil || s.Config.Verifier == nil {
		m.OpenAPIEndpoint = ""
	}
	writeJSON(w, http.StatusOK, m)
}

// handleMCP serves MCP JSON-RPC (tools/list, tools/call, initialize).
// Authorization bearer is preferred over body tokens. JSON-RPC errors stay in
// the body (HTTP 200) except for oversized/malformed transport failures.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if s.Config.MCP == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, s.Config.MaxBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	if int64(len(body)) > s.Config.MaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
		return
	}
	token := ""
	if creds, err := s.extractCredentials(r); err == nil {
		token = creds.Token
	}
	out, err := s.Config.MCP.HandleWithToken(r.Context(), body, token)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "mcp"})
		return
	}
	if out == nil {
		// Notification — empty 204.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
	_, _ = w.Write([]byte("\n"))
}

// handleOpenAPI returns a capability-filtered OpenAPI 3 document.
// Unauthenticated / unknown token → empty paths except the generic execute envelope
// (fail closed: no tool schema leak).
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if s.Config.Registry == nil || s.Config.Verifier == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	var specs []catalog.ToolSpec
	creds, err := s.extractCredentials(r)
	if err == nil && creds.Token != "" {
		if id, aerr := s.Config.Verifier.Authenticate(r.Context(), creds); aerr == nil {
			specs = catalog.Build(s.Config.Registry, catalog.ForCapabilities(id.Capabilities))
		}
	}
	doc := catalog.OpenAPI("loom", specs, catalog.OpenAPIOptions{})
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.Config.MetricsPublic {
		if s.Config.MetricsAuth == nil || !s.Config.MetricsAuth(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "metrics authorization required"})
			return
		}
	}
	w.Header().Set(core.ProtocolHeader, core.ProtocolVersion)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	if s.Config.Metrics != nil {
		_, _ = io.WriteString(w, s.Config.Metrics.Prometheus())
	}
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.Config.Ready != nil {
		if err := s.Config.Ready(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "error": "dependency"})
			return
		}
	}
	if s.RT == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

type executeBody struct {
	Operation        string            `json:"operation"`
	OperationVersion string            `json:"operation_version,omitempty"`
	Boundary         string            `json:"boundary"`
	Input            map[string]any    `json:"input"`
	Fields           []string          `json:"fields"`
	IdempotencyKey   string            `json:"idempotency_key"`
	ApprovalToken    string            `json:"approval_token"`
	Resource         *core.ResourceRef `json:"resource"`
	Metadata         map[string]string `json:"metadata"`
	// Delegation optional untrusted claim; runtime validates.
	Delegation *core.DelegationChain `json:"delegation"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.Config.MaxBodyBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	if int64(len(body)) > s.Config.MaxBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
		return
	}

	var eb executeBody
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if len(body) > 0 {
		if err := dec.Decode(&eb); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
	}
	if eb.Operation == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "operation required"})
		return
	}

	creds, err := s.extractCredentials(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "credentials"})
		return
	}

	md := eb.Metadata
	if md == nil {
		md = map[string]string{}
	}
	// Adapters may record hostile headers for audit/policy; never honor them as grants.
	md["adapter"] = "http"
	md["remote_addr"] = stripPort(r.RemoteAddr)
	md["user_agent"] = truncate(r.UserAgent(), 200)
	applyHostileHeaders(md, r)
	// Do not pass through authorization header into metadata.

	idem := eb.IdempotencyKey
	if idem == "" {
		idem = r.Header.Get("Idempotency-Key")
	}
	approval := eb.ApprovalToken
	if approval == "" {
		approval = r.Header.Get("X-Approval-Token")
	}

	req := core.Request{
		Operation:        eb.Operation,
		OperationVersion: eb.OperationVersion,
		Credentials:      creds,
		Delegation:       eb.Delegation,
		Boundary:         core.BoundaryID(eb.Boundary),
		Resource:         eb.Resource,
		Input:            eb.Input,
		Fields:           eb.Fields,
		IdempotencyKey:   idem,
		ApprovalToken:    approval,
		Metadata:         md,
		TraceID:          r.Header.Get("X-Trace-Id"),
	}

	resp := s.RT.Execute(r.Context(), req)
	writeExecuteResponse(w, resp)
}

func (s *Server) extractCredentials(r *http.Request) (core.Credentials, error) {
	return ExtractCredentials(r, s.Config.RequireMTLS)
}

// ExtractCredentials maps HTTP auth into Loom credentials.
// mTLS: only when a verified peer cert is present (CredentialsFromCertificate).
// Dual auth never ORs privileges: RequireMTLS or empty bearer → mTLS; else bearer only.
func ExtractCredentials(r *http.Request, requireMTLS bool) (core.Credentials, error) {
	if r == nil {
		return core.Credentials{}, fmt.Errorf("nil request")
	}
	// Prefer mTLS when client cert present
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// PeerCertificates contains presented certificates even when the TLS
		// server only requested a client certificate. VerifiedChains proves
		// that the configured trust policy accepted the peer.
		if len(r.TLS.VerifiedChains) > 0 {
			leaf := r.TLS.PeerCertificates[0]
			creds := identity.CredentialsFromCertificate(leaf)
			auth := r.Header.Get("Authorization")
			if requireMTLS || auth == "" {
				return creds, nil
			}
		} else if requireMTLS {
			return core.Credentials{}, fmt.Errorf("mtls peer certificate was not verified")
		}
		// Both presented without RequireMTLS: bearer only (not combined).
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		if requireMTLS {
			return core.Credentials{}, fmt.Errorf("client certificate required")
		}
		return core.Credentials{}, nil
	}
	token := bearer(auth)
	if token == "" {
		return core.Credentials{}, fmt.Errorf("invalid authorization")
	}
	return core.Credentials{Scheme: "bearer", Token: token}, nil
}

// applyHostileHeaders records bypass/admin-override headers as metadata
// tripwires for policy. They never grant privilege.
func applyHostileHeaders(md map[string]string, r *http.Request) {
	if md == nil || r == nil {
		return
	}
	if r.Header.Get("X-Loom-Bypass") != "" {
		md["x-loom-bypass"] = "1"
	}
	if r.Header.Get("X-Admin-Override") != "" {
		md["x-admin-override"] = "1"
	}
}

// Handler is a backward-compatible single-endpoint adapter.
type Handler struct {
	RT *runtime.Runtime
}

// ServeHTTP implements http.Handler for POST-only execute (legacy).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s, err := NewServer(h.RT, ServerConfig{MaxBodyBytes: defaultMaxBody})
	if err != nil {
		http.Error(w, `{"error":"runtime not configured"}`, http.StatusInternalServerError)
		return
	}
	s.handleExecute(w, r)
}

// middleware applies security headers, edge rate limits, and basic request hygiene.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers (API, not browser app — still set conservative defaults)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Reject TRACE/TRACK
		if r.Method == http.MethodTrace || strings.EqualFold(r.Method, "TRACK") {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		// Edge rate limit (fail closed). Skip health probes.
		path := r.URL.Path
		if s.rl != nil && path != "/healthz" && path != "/readyz" {
			if !s.rl.allow(clientIP(r)) {
				w.Header().Set("Retry-After", "1")
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Handler returns the http.Handler for tests / custom listeners.
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// ListenAndServe starts the server (blocking).
func (s *Server) ListenAndServe() error {
	if s.Config.RequireTLS {
		return fmt.Errorf("loom http: plaintext listener refused; use ListenAndServeTLS or configure a trusted TLS proxy")
	}
	if s.Config.Logger != nil {
		s.Config.Logger.Printf("loom http listening on %s", s.Config.Addr)
	}
	return s.http.ListenAndServe()
}

// ListenAndServeTLS starts TLS.
func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	return s.http.ListenAndServeTLS(certFile, keyFile)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func writeExecuteResponse(w http.ResponseWriter, resp core.Response) {
	w.Header().Set(core.ProtocolHeader, core.ProtocolVersion)
	if resp.TraceID != "" {
		w.Header().Set("X-Trace-Id", resp.TraceID)
	}
	status := http.StatusOK
	if !resp.Allowed {
		status = http.StatusForbidden
		if resp.Denial != nil {
			switch resp.Denial.Reason {
			case core.ReasonUnauthenticated:
				status = http.StatusUnauthorized
			case core.ReasonQuotaExceeded:
				status = http.StatusTooManyRequests
			case core.ReasonSchemaInvalid, core.ReasonOperationUnknown:
				status = http.StatusBadRequest
			case core.ReasonApprovalRequired:
				status = http.StatusFailedDependency
			case core.ReasonIdempotencyConflict:
				status = http.StatusConflict
			case core.ReasonGuardrail:
				status = http.StatusUnprocessableEntity
			}
		}
	}
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(core.ProtocolHeader, core.ProtocolVersion)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func bearer(h string) string {
	const p = "Bearer "
	if len(h) >= len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
