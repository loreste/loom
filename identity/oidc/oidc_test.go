package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/loreste/loom/core"
)

func TestVerifierValidTokenAndClaimMapping(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()

	verifier, err := NewVerifier(nilContext(), Config{
		Issuer:            server.URL,
		Audience:          "loom-client",
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        server.Client(),
		Now:               func() time.Time { return clock },
		ClaimBoundary:     "tenant_id",
		ClaimCapabilities: "capabilities",
		ClaimRoles:        "roles",
		RoleCapabilities:  map[string][]string{"operator": {"payment.read"}},
		ClaimAttributes:   map[string]string{"email": "email"},
		RequireBoundary:   true,
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	token := signToken(t, keys["key-1"], "key-1", map[string]any{
		"iss":          server.URL,
		"aud":          "loom-client",
		"sub":          "user-123",
		"type":         "service",
		"tenant_id":    "tenant-a",
		"capabilities": []string{"catalog.read"},
		"roles":        []string{"operator"},
		"email":        "operator@example.test",
		"iat":          clock.Add(-time.Minute).Unix(),
		"exp":          clock.Add(time.Hour).Unix(),
	})
	identity, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if identity.ID != "user-123" || identity.Type != "service" || identity.Boundary != "tenant-a" {
		t.Fatalf("identity mapping = %#v", identity)
	}
	if !contains(identity.Capabilities, "catalog.read") || !contains(identity.Capabilities, "payment.read") {
		t.Fatalf("capabilities = %#v", identity.Capabilities)
	}
	if identity.Attributes["email"] != "operator@example.test" {
		t.Fatalf("attributes = %#v", identity.Attributes)
	}
	if health := verifier.Health(); !health.Ready || health.JWKSRefreshSuccesses == 0 {
		t.Fatalf("health = %#v", health)
	}
}

func TestVerifierRejectsIssuerAudienceAlgorithmAndRequiredClaims(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{})

	tests := []struct {
		name   string
		claims map[string]any
	}{
		{name: "wrong issuer", claims: testClaims(server.URL+"/wrong", clock)},
		{name: "wrong audience", claims: func() map[string]any { c := testClaims(server.URL, clock); c["aud"] = "other"; return c }()},
		{name: "missing exp", claims: func() map[string]any { c := testClaims(server.URL, clock); delete(c, "exp"); return c }()},
		{name: "missing iat", claims: func() map[string]any { c := testClaims(server.URL, clock); delete(c, "iat"); return c }()},
		{name: "future nbf", claims: func() map[string]any {
			c := testClaims(server.URL, clock)
			c["nbf"] = clock.Add(time.Minute).Unix()
			return c
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signToken(t, keys["key-1"], "key-1", test.claims)
			if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
				t.Fatal("Authenticate() unexpectedly succeeded")
			}
		})
	}
}

func TestVerifierRejectsUnsupportedAlgorithmConfiguration(t *testing.T) {
	server, _ := newOIDCTestServer(t)
	defer server.Close()
	for _, algorithm := range []string{"none", ""} {
		_, err := NewVerifier(nilContext(), Config{
			Issuer:            server.URL,
			Audience:          "loom-client",
			AllowedAlgorithms: []string{algorithm},
			HTTPClient:        server.Client(),
		})
		if err == nil {
			t.Fatalf("algorithm %q unexpectedly accepted", algorithm)
		}
	}
}

func TestVerifierRefreshesUnknownKeyID(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{})
	first := signToken(t, keys["key-1"], "key-1", testClaims(server.URL, clock))
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "oidc", Token: first}); err != nil {
		t.Fatalf("first Authenticate() error = %v", err)
	}
	server.Config.Handler.(*oidcHandler).setKeys(keys)
	claims := testClaims(server.URL, clock)
	claims["sub"] = "rotated-user"
	second := signToken(t, keys["key-2"], "key-2", claims)
	identity, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: second})
	if err != nil {
		t.Fatalf("rotated Authenticate() error = %v", err)
	}
	if identity.ID != "rotated-user" || verifier.Health().JWKSRefreshSuccesses < 2 {
		t.Fatalf("rotation identity/health = %#v / %#v", identity, verifier.Health())
	}
}

func TestVerifierRejectsBoundaryMismatchAndOversizedJWKS(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{RequireBoundary: true})
	token := signToken(t, keys["key-1"], "key-1", testClaims(server.URL, clock))
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{
		Scheme: "bearer", Token: token, Claims: map[string]string{"tenant_id": "tenant-b"},
	}); err == nil {
		t.Fatal("boundary mismatch unexpectedly succeeded")
	}

	server.Config.Handler.(*oidcHandler).oversized = true
	server.Config.Handler.(*oidcHandler).setKeys(keys)
	claims := testClaims(server.URL, clock)
	claims["sub"] = "new-key-user"
	rotated := signToken(t, keys["key-2"], "key-2", claims)
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: rotated}); err == nil {
		t.Fatal("oversized JWKS unexpectedly succeeded")
	}
}

func TestVerifierIntrospectionFailsClosed(t *testing.T) {
	server, _ := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, time.Now().UTC(), Config{
		Introspector: IntrospectorFunc(func(_ context.Context, _ string) (bool, error) {
			return false, fmt.Errorf("provider unavailable")
		}),
	})
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: "opaque"}); err == nil {
		t.Fatal("inactive token unexpectedly succeeded")
	}
}

func newTestVerifier(t *testing.T, server *httptest.Server, clock time.Time, extra Config) *Verifier {
	t.Helper()
	config := Config{
		Issuer:            server.URL,
		Audience:          "loom-client",
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        server.Client(),
		Now:               func() time.Time { return clock },
		ClaimBoundary:     "tenant_id",
		RequireBoundary:   true,
	}
	if extra.RequireBoundary {
		config.RequireBoundary = true
	}
	if extra.ClaimBoundary != "" {
		config.ClaimBoundary = extra.ClaimBoundary
	}
	if extra.Introspector != nil {
		config.Introspector = extra.Introspector
	}
	verifier, err := NewVerifier(nilContext(), config)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return verifier
}

func testClaims(issuer string, now time.Time) map[string]any {
	return map[string]any{
		"iss":       issuer,
		"aud":       "loom-client",
		"sub":       "user-123",
		"tenant_id": "tenant-a",
		"iat":       now.Add(-time.Minute).Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	}
}

type oidcHandler struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PrivateKey
	oversized bool
}

func (h *oidcHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, map[string]any{
			"issuer":                                requestURLIssuer(request),
			"jwks_uri":                              requestURLIssuer(request) + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/jwks":
		if h.oversized {
			_, _ = w.Write([]byte(strings.Repeat("x", defaultMaxJWKSSize+1)))
			return
		}
		publicKeys := make([]map[string]any, 0, len(h.keys))
		for kid, key := range h.keys {
			publicKeys = append(publicKeys, map[string]any{
				"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			})
		}
		writeJSON(w, map[string]any{"keys": publicKeys})
	default:
		http.NotFound(w, request)
	}
}

func (h *oidcHandler) setKeys(keys map[string]*rsa.PrivateKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keys = keys
}

func newOIDCTestServer(t *testing.T) (*httptest.Server, map[string]*rsa.PrivateKey) {
	t.Helper()
	keys := map[string]*rsa.PrivateKey{
		"key-1": generateRSAKey(t),
		"key-2": generateRSAKey(t),
	}
	handler := &oidcHandler{keys: map[string]*rsa.PrivateKey{"key-1": keys["key-1"]}}
	server := httptest.NewTLSServer(handler)
	return server, keys
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	message := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15() error = %v", err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func requestURLIssuer(request *http.Request) string {
	return "https://" + request.Host
}

// nilContext keeps the tests explicit without allowing a nil context into
// the production verifier API.
func nilContext() context.Context { return context.Background() }
