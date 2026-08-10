// Package oidc provides a production-oriented OpenID Connect verifier for
// Loom. It authenticates bearer credentials into core.Identity; it does not
// grant operation access or replace Loom policy evaluation.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/loreste/loom/core"
)

const (
	defaultClockSkew        = 30 * time.Second
	defaultMaxTokenBytes    = 8 << 10
	defaultMaxDiscoverySize = 1 << 20
	defaultMaxJWKSSize      = 4 << 20
	defaultHTTPTimeout      = 10 * time.Second
	maxTokenBytes           = 1 << 20
	maxDiscoverySize        = 16 << 20
	maxJWKSSize             = 32 << 20
	maxHTTPTimeout          = 2 * time.Minute
)

// Introspector is an optional revocation or active-token check. Implementations
// must not log or retain the token and should fail closed on uncertainty.
type Introspector interface {
	Introspect(context.Context, string) (bool, error)
}

// IntrospectorFunc adapts a function to Introspector.
type IntrospectorFunc func(context.Context, string) (bool, error)

func (f IntrospectorFunc) Introspect(ctx context.Context, token string) (bool, error) {
	return f(ctx, token)
}

// Config controls discovery, verification, and claim mapping. Issuer,
// Audience, and AllowedAlgorithms are required. Claim names are configurable
// because providers do not use one universal tenant or capability vocabulary.
type Config struct {
	Issuer            string
	Audience          string
	AllowedAlgorithms []string
	ClockSkew         time.Duration
	Now               func() time.Time
	MaxTokenBytes     int
	MaxDiscoveryBytes int64
	MaxJWKSBytes      int64
	HTTPClient        *http.Client

	ClaimPrincipal       string
	ClaimType            string
	ClaimBoundary        string
	ClaimCapabilities    string
	ClaimRoles           string
	ClaimAttributes      map[string]string
	RoleCapabilities     map[string][]string
	RequiredCapabilities []string
	RequireBoundary      bool
	MaxTokenAge          time.Duration
	Introspector         Introspector
}

// Health is a bounded, non-sensitive view of discovery and JWKS activity.
// It contains no token, subject, tenant, or execution identifiers.
type Health struct {
	Ready                   bool
	Issuer                  string
	LastDiscoveryAt         time.Time
	LastJWKSRefreshAt       time.Time
	DiscoverySuccesses      uint64
	DiscoveryFailures       uint64
	JWKSRefreshSuccesses    uint64
	JWKSRefreshFailures     uint64
	Authentications         uint64
	RejectedAuthentications uint64
}

type counters struct {
	lastDiscovery      atomic.Int64
	lastJWKS           atomic.Int64
	discoverySuccesses atomic.Uint64
	discoveryFailures  atomic.Uint64
	jwksSuccesses      atomic.Uint64
	jwksFailures       atomic.Uint64
	authentications    atomic.Uint64
	rejected           atomic.Uint64
}

// Verifier authenticates OIDC bearer tokens. The underlying library performs
// signature validation and refreshes remote keys when an unknown key ID is
// encountered; this wrapper adds strict configuration, bounded HTTP bodies,
// claim mapping, and safe health counters.
type Verifier struct {
	verifier *gooidc.IDTokenVerifier
	cfg      Config
	health   *counters
}

// NewVerifier performs issuer discovery before returning. Discovery errors,
// malformed issuer URLs, missing audience, and an empty algorithm allowlist
// fail closed during construction.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	health := &counters{}
	client := boundedClient(cfg, health)
	providerCtx := gooidc.ClientContext(ctx, client)
	provider, err := gooidc.NewProvider(providerCtx, cfg.Issuer)
	if err != nil {
		health.discoveryFailures.Add(1)
		return nil, fmt.Errorf("identity/oidc: discovery failed: %w", err)
	}
	// SkipExpiryCheck: go-oidc applies zero leeway to exp and a hard-coded
	// 5-minute nbf leeway. Loom enforces exp/nbf/iat with Config.ClockSkew so
	// deployments get a single, conservative, configurable skew budget.
	verifier := provider.VerifierContext(providerCtx, &gooidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: append([]string(nil), cfg.AllowedAlgorithms...),
		Now:                  cfg.Now,
		SkipExpiryCheck:      true,
	})
	// Fetch the key set now. go-oidc otherwise loads it lazily on the first
	// token, which would leave Health().Ready false until real traffic
	// arrived — a readiness probe that can never pass. Failing here also
	// surfaces an unreachable JWKS endpoint at startup rather than on a
	// caller's first authenticated request.
	if err := prefetchJWKS(providerCtx, client, provider); err != nil {
		return nil, fmt.Errorf("identity/oidc: jwks fetch failed: %w", err)
	}
	return &Verifier{verifier: verifier, cfg: cfg, health: health}, nil
}

// prefetchJWKS reads the key set through the bounded client so the size limit
// and readiness counters apply exactly as they do to a refresh.
func prefetchJWKS(ctx context.Context, client *http.Client, provider *gooidc.Provider) error {
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return err
	}
	if strings.TrimSpace(metadata.JWKSURL) == "" {
		return fmt.Errorf("discovery document does not advertise jwks_uri")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.JWKSURL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	// Drain to EOF: the bounded body records the refresh outcome on the final
	// read, so an unread body would leave the counters untouched.
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("jwks endpoint returned %s", response.Status)
	}
	return nil
}

func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("%w: nil oidc config", core.ErrInvalidArgument)
	}
	u, err := url.Parse(strings.TrimSpace(cfg.Issuer))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: issuer must be an absolute URL without credentials or fragment", core.ErrInvalidArgument)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: issuer must use https", core.ErrInvalidArgument)
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return fmt.Errorf("%w: audience is required", core.ErrInvalidArgument)
	}
	if len(cfg.AllowedAlgorithms) == 0 {
		return fmt.Errorf("%w: at least one signing algorithm is required", core.ErrInvalidArgument)
	}
	seenAlgorithms := make(map[string]struct{}, len(cfg.AllowedAlgorithms))
	for i, algorithm := range cfg.AllowedAlgorithms {
		algorithm = strings.TrimSpace(algorithm)
		if algorithm == "" || strings.EqualFold(algorithm, "none") {
			return fmt.Errorf("%w: invalid signing algorithm at index %d", core.ErrInvalidArgument, i)
		}
		if _, exists := seenAlgorithms[algorithm]; exists {
			return fmt.Errorf("%w: duplicate signing algorithm %q", core.ErrInvalidArgument, algorithm)
		}
		seenAlgorithms[algorithm] = struct{}{}
		cfg.AllowedAlgorithms[i] = algorithm
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxTokenBytes <= 0 {
		cfg.MaxTokenBytes = defaultMaxTokenBytes
	}
	if cfg.MaxDiscoveryBytes <= 0 {
		cfg.MaxDiscoveryBytes = defaultMaxDiscoverySize
	}
	if cfg.MaxJWKSBytes <= 0 {
		cfg.MaxJWKSBytes = defaultMaxJWKSSize
	}
	if cfg.MaxTokenAge < 0 {
		return fmt.Errorf("%w: max token age cannot be negative", core.ErrInvalidArgument)
	}
	if cfg.ClaimPrincipal == "" {
		cfg.ClaimPrincipal = "sub"
	}
	if cfg.ClaimType == "" {
		cfg.ClaimType = "type"
	}
	if cfg.RequireBoundary && strings.TrimSpace(cfg.ClaimBoundary) == "" {
		return fmt.Errorf("%w: boundary claim is required when boundary enforcement is enabled", core.ErrInvalidArgument)
	}
	if cfg.HTTPClient != nil && cfg.HTTPClient.Timeout < 0 {
		return fmt.Errorf("%w: http timeout cannot be negative", core.ErrInvalidArgument)
	}
	if cfg.MaxTokenBytes > maxTokenBytes || cfg.MaxDiscoveryBytes > maxDiscoverySize || cfg.MaxJWKSBytes > maxJWKSSize {
		return fmt.Errorf("%w: configured response limits exceed safe maximums", core.ErrInvalidArgument)
	}
	if cfg.HTTPClient != nil && cfg.HTTPClient.Timeout > maxHTTPTimeout {
		return fmt.Errorf("%w: http timeout exceeds safe maximum", core.ErrInvalidArgument)
	}
	return nil
}

func boundedClient(cfg Config, health *counters) *http.Client {
	client := &http.Client{Timeout: defaultHTTPTimeout}
	if cfg.HTTPClient != nil {
		clone := *cfg.HTTPClient
		client = &clone
		if client.Timeout == 0 {
			client.Timeout = defaultHTTPTimeout
		}
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = &boundedTransport{
		base:      base,
		health:    health,
		discovery: cfg.MaxDiscoveryBytes,
		jwks:      cfg.MaxJWKSBytes,
	}
	return client
}

// Authenticate verifies only the credential. Authorization remains the
// responsibility of runtime.Runtime.Execute.
func (v *Verifier) Authenticate(ctx context.Context, creds core.Credentials) (core.Identity, error) {
	if v == nil || v.verifier == nil || v.health == nil {
		return core.Identity{}, fmt.Errorf("identity/oidc: verifier is not configured")
	}
	if err := ctx.Err(); err != nil {
		return core.Identity{}, err
	}
	scheme := strings.ToLower(strings.TrimSpace(creds.Scheme))
	if scheme != "bearer" && scheme != "oidc" {
		return core.Identity{}, fmt.Errorf("identity/oidc: unsupported credential scheme")
	}
	if creds.Token == "" || len(creds.Token) > v.cfg.MaxTokenBytes {
		v.health.rejected.Add(1)
		return core.Identity{}, fmt.Errorf("identity/oidc: token rejected")
	}
	if v.cfg.Introspector != nil {
		active, err := v.cfg.Introspector.Introspect(ctx, creds.Token)
		if err != nil || !active {
			v.health.rejected.Add(1)
			if err != nil {
				return core.Identity{}, fmt.Errorf("identity/oidc: token introspection failed")
			}
			return core.Identity{}, fmt.Errorf("identity/oidc: token is inactive")
		}
	}

	token, err := v.verifier.Verify(ctx, creds.Token)
	if err != nil {
		v.health.rejected.Add(1)
		return core.Identity{}, fmt.Errorf("identity/oidc: token verification failed")
	}
	v.health.authentications.Add(1)

	claims := make(map[string]any)
	if err := token.Claims(&claims); err != nil {
		v.health.rejected.Add(1)
		return core.Identity{}, fmt.Errorf("identity/oidc: claims unavailable")
	}
	if err := v.validateTimes(token, claims); err != nil {
		v.health.rejected.Add(1)
		return core.Identity{}, err
	}

	principal, ok := claimString(claims, v.cfg.ClaimPrincipal)
	if !ok || principal == "" {
		v.health.rejected.Add(1)
		return core.Identity{}, fmt.Errorf("identity/oidc: required subject claim missing")
	}
	typ := "user"
	if configured, exists := claimString(claims, v.cfg.ClaimType); exists && configured != "" {
		typ = configured
	}
	boundary, boundaryOK := claimString(claims, v.cfg.ClaimBoundary)
	if v.cfg.RequireBoundary && (!boundaryOK || boundary == "") {
		v.health.rejected.Add(1)
		return core.Identity{}, fmt.Errorf("identity/oidc: required boundary claim missing")
	}
	if v.cfg.ClaimBoundary != "" {
		if expected, exists := creds.Claims[v.cfg.ClaimBoundary]; exists && expected != "" && expected != boundary {
			v.health.rejected.Add(1)
			return core.Identity{}, fmt.Errorf("identity/oidc: boundary claim mismatch")
		}
	}

	capabilities := append([]string(nil), claimStrings(claims, v.cfg.ClaimCapabilities)...)
	for _, role := range claimStrings(claims, v.cfg.ClaimRoles) {
		capabilities = append(capabilities, v.cfg.RoleCapabilities[role]...)
	}
	capabilities = uniqueStrings(capabilities)
	for _, required := range v.cfg.RequiredCapabilities {
		if !contains(capabilities, required) {
			v.health.rejected.Add(1)
			return core.Identity{}, fmt.Errorf("identity/oidc: required capability missing")
		}
	}

	attributes := make(map[string]string, len(v.cfg.ClaimAttributes))
	for claim, attribute := range v.cfg.ClaimAttributes {
		if value, exists := claimString(claims, claim); exists {
			attributes[attribute] = value
		}
	}
	return core.Identity{
		ID:           core.PrincipalID(principal),
		Type:         typ,
		Boundary:     core.BoundaryID(boundary),
		Attributes:   attributes,
		Capabilities: capabilities,
		AuthMethod:   "oidc",
	}, nil
}

func (v *Verifier) validateTimes(token *gooidc.IDToken, claims map[string]any) error {
	now := v.cfg.Now()
	if token.Expiry.IsZero() {
		return fmt.Errorf("identity/oidc: exp claim missing")
	}
	// Reject when now is past exp + skew. A token that expired within the
	// configured clock-skew window remains valid; anything older is denied.
	if now.After(token.Expiry.Add(v.cfg.ClockSkew)) {
		return fmt.Errorf("identity/oidc: token expired")
	}
	issuedAt, ok := numericDate(claims["iat"])
	if !ok {
		return fmt.Errorf("identity/oidc: iat claim missing")
	}
	if issuedAt.After(now.Add(v.cfg.ClockSkew)) {
		return fmt.Errorf("identity/oidc: token issued in the future")
	}
	if v.cfg.MaxTokenAge > 0 && now.After(issuedAt.Add(v.cfg.MaxTokenAge).Add(v.cfg.ClockSkew)) {
		return fmt.Errorf("identity/oidc: token is too old")
	}
	if raw, exists := claims["nbf"]; exists {
		// Stricter than go-oidc's fixed 5-minute nbf leeway: only the
		// configured ClockSkew is accepted.
		if notBefore, valid := numericDate(raw); !valid || notBefore.After(now.Add(v.cfg.ClockSkew)) {
			return fmt.Errorf("identity/oidc: token is not yet valid")
		}
	}
	return nil
}

// Health returns a copy of bounded readiness and refresh counters.
func (v *Verifier) Health() Health {
	if v == nil || v.health == nil {
		return Health{}
	}
	discoverySuccesses := v.health.discoverySuccesses.Load()
	jwksRefreshSuccesses := v.health.jwksSuccesses.Load()
	return Health{
		Ready:                   discoverySuccesses > 0 && jwksRefreshSuccesses > 0,
		Issuer:                  v.cfg.Issuer,
		LastDiscoveryAt:         unixTime(v.health.lastDiscovery.Load()),
		LastJWKSRefreshAt:       unixTime(v.health.lastJWKS.Load()),
		DiscoverySuccesses:      discoverySuccesses,
		DiscoveryFailures:       v.health.discoveryFailures.Load(),
		JWKSRefreshSuccesses:    jwksRefreshSuccesses,
		JWKSRefreshFailures:     v.health.jwksFailures.Load(),
		Authentications:         v.health.authentications.Load(),
		RejectedAuthentications: v.health.rejected.Load(),
	}
}

// ReadyCheck adapts Health to a readiness probe for bootstrap.Config.
// ReadyChecks. It fails while the verifier has not completed both issuer
// discovery and a JWKS refresh, so a process that cannot reach its issuer is
// reported unready rather than denying every authenticated request.
func (v *Verifier) ReadyCheck() func(context.Context) error {
	return func(context.Context) error {
		if !v.Health().Ready {
			return fmt.Errorf("identity/oidc: verifier has not completed discovery and JWKS refresh")
		}
		return nil
	}
}

func unixTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

type responseKind uint8

const (
	discoveryResponse responseKind = iota + 1
	jwksResponse
)

type boundedTransport struct {
	base      http.RoundTripper
	health    *counters
	discovery int64
	jwks      int64
}

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	kind := jwksResponse
	if strings.Contains(req.URL.Path, "/.well-known/openid-configuration") {
		kind = discoveryResponse
	}
	if err != nil {
		t.record(kind, false)
		return nil, err
	}
	limit := t.jwks
	if kind == discoveryResponse {
		limit = t.discovery
	}
	if response.ContentLength > limit {
		_ = response.Body.Close()
		t.record(kind, false)
		return nil, fmt.Errorf("identity/oidc: upstream response exceeds configured limit")
	}
	response.Body = &boundedBody{body: response.Body, remaining: limit, kind: kind, health: t.health, statusOK: response.StatusCode >= 200 && response.StatusCode < 300}
	return response, nil
}

func (t *boundedTransport) record(kind responseKind, success bool) {
	if kind == discoveryResponse {
		if success {
			t.health.discoverySuccesses.Add(1)
			t.health.lastDiscovery.Store(time.Now().UTC().UnixNano())
		} else {
			t.health.discoveryFailures.Add(1)
		}
		return
	}
	if success {
		t.health.jwksSuccesses.Add(1)
		t.health.lastJWKS.Store(time.Now().UTC().UnixNano())
	} else {
		t.health.jwksFailures.Add(1)
	}
}

type boundedBody struct {
	body      io.ReadCloser
	remaining int64
	kind      responseKind
	health    *counters
	statusOK  bool
	completed bool
	failed    bool
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.failed {
		return 0, fmt.Errorf("identity/oidc: upstream response exceeds configured limit")
	}
	if b.remaining <= 0 {
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n > 0 || (err == nil && n == 0) {
			b.failed = true
			b.record(false)
			return 0, fmt.Errorf("identity/oidc: upstream response exceeds configured limit")
		}
		if errors.Is(err, io.EOF) {
			b.record(b.statusOK)
			return 0, io.EOF
		}
		b.failed = true
		b.record(false)
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	if errors.Is(err, io.EOF) {
		b.record(b.statusOK)
	} else if err != nil {
		b.failed = true
		b.record(false)
	}
	return n, err
}

func (b *boundedBody) Close() error { return b.body.Close() }

func (b *boundedBody) record(success bool) {
	if b.completed || b.failed && success {
		return
	}
	if success {
		b.completed = true
	} else {
		b.failed = true
	}
	if b.health != nil {
		transport := boundedTransport{health: b.health}
		transport.record(b.kind, success)
	}
}

func claimString(claims map[string]any, name string) (string, bool) {
	value, exists := claims[name]
	if !exists {
		return "", false
	}
	text, ok := value.(string)
	return strings.TrimSpace(text), ok && strings.TrimSpace(text) != ""
}

func claimStrings(claims map[string]any, name string) []string {
	value, exists := claims[name]
	if !exists {
		return nil
	}
	var values []string
	switch typed := value.(type) {
	case string:
		values = []string{typed}
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
	case []string:
		values = append(values, typed...)
	}
	return uniqueStrings(values)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func numericDate(value any) (time.Time, bool) {
	var seconds float64
	switch typed := value.(type) {
	case float64:
		seconds = typed
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	case string:
		parsed, err := json.Number(typed).Float64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	default:
		return time.Time{}, false
	}
	if seconds < 0 || seconds > float64(^uint64(0)>>1) {
		return time.Time{}, false
	}
	whole := int64(seconds)
	nanos := int64((seconds - float64(whole)) * float64(time.Second))
	return time.Unix(whole, nanos), true
}
