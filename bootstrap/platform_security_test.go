package bootstrap_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
)

// TestDisableDemoPrincipals verifies the opt-out removes the publicly-known
// demo tokens (adversarial: alice-secret-token must NOT authenticate).
func TestDisableDemoPrincipals(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{DisableDemoPrincipals: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	resp := p.Runtime.Execute(context.Background(), core.Request{
		Operation:   "document.read",
		Credentials: core.Credentials{Scheme: "bearer", Token: "alice-secret-token"},
		Boundary:    "dev",
	})
	if resp.Allowed {
		t.Fatal("demo token authenticated despite DisableDemoPrincipals")
	}
}

// TestRequireDurableRefusesDemoPrincipals: production-ish config must not
// start with publicly-known demo tokens unless explicitly disabled.
func TestRequireDurableRefusesDemoPrincipals(t *testing.T) {
	if _, err := bootstrap.NewPlatform(bootstrap.Config{RequireDurable: true}); err == nil {
		t.Fatal("expected refusal: RequireDurable with demo principals enabled")
	}
	if _, err := bootstrap.NewPlatform(bootstrap.Config{RequireDurable: true, DisableDemoPrincipals: true}); err == nil {
		t.Fatal("expected refusal when durable stores and identity secret are not configured")
	}
}

// TestMintDemoJWTUsesConfiguredIssuerAudience: demo tokens must verify under
// custom iss/aud (previously hardcoded loom/loom-api).
func TestMintDemoJWTUsesConfiguredIssuerAudience(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		JWTIssuer:   "acme-issuer",
		JWTAudience: "acme-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	tok, err := p.MintDemoJWT("user:alice", "dev", []string{"document.read"}, "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.JWT.Authenticate(context.Background(), core.Credentials{Scheme: "jwt", Token: tok})
	if err != nil {
		t.Fatalf("demo JWT rejected under configured iss/aud: %v", err)
	}
	if id.ID != "user:alice" {
		t.Fatalf("identity = %q", id.ID)
	}
	if !strings.Contains(tok, ".") {
		t.Fatal("not a JWT")
	}
}
