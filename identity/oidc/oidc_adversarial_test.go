package oidc

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/loreste/loom/core"
)

// TestVerifierRejectsAlgorithmConfusion is the classic JWT alg confusion
// suite: a token that claims HS256 (or none) must never verify under an
// RS256-only allowlist, even if the HMAC key is the RSA public modulus.
func TestVerifierRejectsAlgorithmConfusion(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{})

	claims := testClaims(server.URL, clock)

	t.Run("alg none", func(t *testing.T) {
		token := unsignedToken(t, "none", claims)
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
			t.Fatal("alg=none token accepted")
		}
	})

	t.Run("alg HS256 with RSA public material as secret", func(t *testing.T) {
		// Attacker signs with HMAC using the published RSA modulus bytes as the
		// shared secret — classic confusion against verifiers that trust header.alg.
		pubN := keys["key-1"].PublicKey.N.Bytes()
		token := hmacToken(t, "HS256", pubN, claims)
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
			t.Fatal("HS256 algorithm-confusion token accepted under RS256 allowlist")
		}
	})

	t.Run("alg RS384 when only RS256 allowed", func(t *testing.T) {
		token := signTokenWithAlg(t, keys["key-1"], "key-1", "RS384", claims)
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
			t.Fatal("RS384 token accepted under RS256-only allowlist")
		}
	})

	t.Run("wrong RSA signature", func(t *testing.T) {
		token := signToken(t, keys["key-1"], "key-1", claims)
		// Corrupt the signature tail.
		parts := strings.Split(token, ".")
		parts[2] = base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature-bytes!!"))
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: strings.Join(parts, ".")}); err == nil {
			t.Fatal("forged signature accepted")
		}
	})
}

// TestVerifierClockSkewOnExpiry ensures Config.ClockSkew is actually applied
// to exp (previously go-oidc rejected with zero leeway, ignoring the config).
func TestVerifierClockSkewOnExpiry(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()

	verifier, err := NewVerifier(nilContext(), Config{
		Issuer:            server.URL,
		Audience:          "loom-client",
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        server.Client(),
		Now:               func() time.Time { return clock },
		ClockSkew:         30 * time.Second,
		ClaimBoundary:     "tenant_id",
		RequireBoundary:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expired within skew is accepted", func(t *testing.T) {
		claims := testClaims(server.URL, clock)
		// Expired 10s ago — within 30s skew.
		claims["exp"] = clock.Add(-10 * time.Second).Unix()
		claims["iat"] = clock.Add(-2 * time.Minute).Unix()
		token := signToken(t, keys["key-1"], "key-1", claims)
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err != nil {
			t.Fatalf("token expired within clock skew rejected: %v", err)
		}
	})

	t.Run("expired beyond skew is rejected", func(t *testing.T) {
		claims := testClaims(server.URL, clock)
		claims["exp"] = clock.Add(-31 * time.Second).Unix()
		claims["iat"] = clock.Add(-2 * time.Minute).Unix()
		token := signToken(t, keys["key-1"], "key-1", claims)
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
			t.Fatal("token expired beyond clock skew accepted")
		}
	})

	t.Run("nbf within skew is accepted", func(t *testing.T) {
		claims := testClaims(server.URL, clock)
		claims["nbf"] = clock.Add(10 * time.Second).Unix()
		token := signToken(t, keys["key-1"], "key-1", claims)
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err != nil {
			t.Fatalf("nbf within clock skew rejected: %v", err)
		}
	})

	t.Run("nbf beyond skew is rejected even if go-oidc 5m leeway would allow", func(t *testing.T) {
		claims := testClaims(server.URL, clock)
		// 2 minutes in the future: go-oidc's fixed 5m leeway would accept this
		// when SkipExpiryCheck is false; Loom's 30s ClockSkew must deny.
		claims["nbf"] = clock.Add(2 * time.Minute).Unix()
		token := signToken(t, keys["key-1"], "key-1", claims)
		if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
			t.Fatal("nbf beyond configured clock skew accepted")
		}
	})
}

// TestVerifierRejectsMissingSubjectAndEmptyPrincipal ensures identity is never
// produced without a concrete principal for policy evaluation.
func TestVerifierRejectsMissingSubjectAndEmptyPrincipal(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{})

	for _, name := range []string{"missing sub", "empty sub", "whitespace sub"} {
		t.Run(name, func(t *testing.T) {
			claims := testClaims(server.URL, clock)
			switch name {
			case "missing sub":
				delete(claims, "sub")
			case "empty sub":
				claims["sub"] = ""
			case "whitespace sub":
				claims["sub"] = "   "
			}
			token := signToken(t, keys["key-1"], "key-1", claims)
			if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
				t.Fatal("token without usable subject accepted")
			}
		})
	}
}

// TestVerifierErrorsNeverEchoToken ensures denials stay free of credential
// material (invariant 11).
func TestVerifierErrorsNeverEchoToken(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{})

	secretMarker := "super-secret-token-value-do-not-leak"
	claims := testClaims(server.URL, clock)
	claims["exp"] = clock.Add(-time.Hour).Unix()
	token := signToken(t, keys["key-1"], "key-1", claims)
	// Also try an opaque garbage token containing the marker.
	cases := []string{token, secretMarker, "bearer." + secretMarker + ".x"}
	for _, raw := range cases {
		_, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: raw})
		if err == nil {
			t.Fatal("expected rejection")
		}
		if strings.Contains(err.Error(), secretMarker) || strings.Contains(err.Error(), raw) {
			t.Fatalf("error echoed credential material: %v", err)
		}
	}
}

// TestVerifierRejectsHTTPIssuerAndCredentialedURL enforces discovery URL
// hygiene — no cleartext issuers and no userinfo in the issuer URL.
func TestVerifierRejectsHTTPIssuerAndCredentialedURL(t *testing.T) {
	for _, issuer := range []string{
		"http://issuer.example/realms/loom",
		"https://user:pass@issuer.example/realms/loom",
		"https://issuer.example/realms/loom#fragment",
		"not-a-url",
		"",
	} {
		_, err := NewVerifier(nilContext(), Config{
			Issuer:            issuer,
			Audience:          "loom-client",
			AllowedAlgorithms: []string{"RS256"},
		})
		if err == nil {
			t.Fatalf("issuer %q unexpectedly accepted", issuer)
		}
	}
}

// TestVerifierRejectsDuplicateAndNoneAlgorithmsInConfig is configuration
// fail-closed: weak or repeated algs must not construct a verifier.
func TestVerifierRejectsDuplicateAndNoneAlgorithmsInConfig(t *testing.T) {
	server, _ := newOIDCTestServer(t)
	defer server.Close()
	cases := [][]string{
		{"none"},
		{"RS256", "RS256"},
		{"RS256", "none"},
		{""},
		nil,
	}
	for _, algs := range cases {
		_, err := NewVerifier(nilContext(), Config{
			Issuer:            server.URL,
			Audience:          "loom-client",
			AllowedAlgorithms: algs,
			HTTPClient:        server.Client(),
		})
		if err == nil {
			t.Fatalf("algorithms %v unexpectedly accepted", algs)
		}
	}
}

// TestVerifierMaxTokenAgeEnforced rejects otherwise-valid tokens older than
// the configured absolute age (session fixation / long-lived token guard).
func TestVerifierMaxTokenAgeEnforced(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier, err := NewVerifier(nilContext(), Config{
		Issuer:            server.URL,
		Audience:          "loom-client",
		AllowedAlgorithms: []string{"RS256"},
		HTTPClient:        server.Client(),
		Now:               func() time.Time { return clock },
		ClockSkew:         time.Second,
		MaxTokenAge:       5 * time.Minute,
		ClaimBoundary:     "tenant_id",
		RequireBoundary:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := testClaims(server.URL, clock)
	claims["iat"] = clock.Add(-10 * time.Minute).Unix()
	claims["exp"] = clock.Add(time.Hour).Unix()
	token := signToken(t, keys["key-1"], "key-1", claims)
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
		t.Fatal("token older than MaxTokenAge accepted")
	}
}

// TestVerifierRequiredCapabilitiesAreNotAuthorization documents that missing
// mapped capabilities deny at the identity boundary only — runtime policy is
// still the authorization authority (invariant 2).
func TestVerifierRequiredCapabilitiesAreNotAuthorization(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier, err := NewVerifier(nilContext(), Config{
		Issuer:               server.URL,
		Audience:             "loom-client",
		AllowedAlgorithms:    []string{"RS256"},
		HTTPClient:           server.Client(),
		Now:                  func() time.Time { return clock },
		ClaimBoundary:        "tenant_id",
		RequireBoundary:      true,
		ClaimCapabilities:    "capabilities",
		RequiredCapabilities: []string{"must.have"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := testClaims(server.URL, clock)
	claims["capabilities"] = []string{"other.cap"}
	token := signToken(t, keys["key-1"], "key-1", claims)
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err == nil {
		t.Fatal("missing required capability accepted")
	}
	// Present capability authenticates — it does not grant operation access.
	claims["capabilities"] = []string{"must.have"}
	token = signToken(t, keys["key-1"], "key-1", claims)
	identity, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if identity.AuthMethod != "oidc" || identity.ID == "" {
		t.Fatalf("identity = %#v", identity)
	}
}

// TestVerifierRejectsCanceledContext fails closed on caller cancellation.
func TestVerifierRejectsCanceledContext(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	token := signToken(t, keys["key-1"], "key-1", testClaims(server.URL, clock))
	if _, err := verifier.Authenticate(ctx, core.Credentials{Scheme: "bearer", Token: token}); err == nil {
		t.Fatal("canceled context accepted")
	}
}

// TestVerifierHealthDoesNotExposeSubjects keeps readiness counters free of
// high-cardinality or sensitive identifiers.
func TestVerifierHealthDoesNotExposeSubjects(t *testing.T) {
	clock := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	server, keys := newOIDCTestServer(t)
	defer server.Close()
	verifier := newTestVerifier(t, server, clock, Config{})
	token := signToken(t, keys["key-1"], "key-1", testClaims(server.URL, clock))
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: token}); err != nil {
		t.Fatal(err)
	}
	// Force a rejection and ensure health remains aggregate-only.
	if _, err := verifier.Authenticate(nilContext(), core.Credentials{Scheme: "bearer", Token: "garbage"}); err == nil {
		t.Fatal("expected reject")
	}
	health := verifier.Health()
	encoded, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "user-123") || strings.Contains(string(encoded), token) {
		t.Fatalf("health leaked identity material: %s", encoded)
	}
	if health.Authentications < 1 || health.RejectedAuthentications < 1 {
		t.Fatalf("health counters not updated: %+v", health)
	}
}

func unsignedToken(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body) + "."
}

func hmacToken(t *testing.T, alg string, secret []byte, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(message))
	return message + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signTokenWithAlg(t *testing.T, key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	// Produce a structurally valid JWT with a non-allowlisted alg header.
	// Signature may not match the alg; the allowlist must reject before trust.
	header, _ := json.Marshal(map[string]any{"alg": alg, "kid": kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}
