package identity_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
)

type stubVerifier struct {
	name string
	ok   bool
}

func (s stubVerifier) Authenticate(_ context.Context, _ core.Credentials) (core.Identity, error) {
	if !s.ok {
		return core.Identity{}, fmt.Errorf("%s reject", s.name)
	}
	return core.Identity{ID: core.PrincipalID(s.name), AuthMethod: s.name}, nil
}

func TestMultiVerifierBearerFallsThroughJWTThenOIDC(t *testing.T) {
	m := identity.NewMultiVerifier(map[string]identity.Verifier{
		"bearer": stubVerifier{name: "bearer", ok: false},
		"jwt":    stubVerifier{name: "jwt", ok: false},
		"oidc":   stubVerifier{name: "oidc", ok: true},
	})
	id, err := m.Authenticate(context.Background(), core.Credentials{Scheme: "bearer", Token: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "oidc" || id.AuthMethod != "oidc" {
		t.Fatalf("identity = %#v", id)
	}
}

func TestMultiVerifierBearerPrefersJWTOverOIDC(t *testing.T) {
	m := identity.NewMultiVerifier(map[string]identity.Verifier{
		"bearer": stubVerifier{name: "bearer", ok: false},
		"jwt":    stubVerifier{name: "jwt", ok: true},
		"oidc":   stubVerifier{name: "oidc", ok: true},
	})
	id, err := m.Authenticate(context.Background(), core.Credentials{Scheme: "bearer", Token: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "jwt" {
		t.Fatalf("want jwt first, got %#v", id)
	}
}

func TestMultiVerifierPreservesPrimaryErrorWhenAlternatesFail(t *testing.T) {
	m := identity.NewMultiVerifier(map[string]identity.Verifier{
		"bearer": stubVerifier{name: "bearer", ok: false},
		"jwt":    stubVerifier{name: "jwt", ok: false},
		"oidc":   stubVerifier{name: "oidc", ok: false},
	})
	_, err := m.Authenticate(context.Background(), core.Credentials{Scheme: "bearer", Token: "x"})
	if err == nil || err.Error() != "bearer reject" {
		t.Fatalf("want primary bearer error, got %v", err)
	}
}

func TestMultiVerifierOIDCSchemeDirect(t *testing.T) {
	m := identity.NewMultiVerifier(map[string]identity.Verifier{
		"oidc": stubVerifier{name: "oidc", ok: true},
	})
	id, err := m.Authenticate(context.Background(), core.Credentials{Scheme: "oidc", Token: "x"})
	if err != nil || id.ID != "oidc" {
		t.Fatalf("id=%#v err=%v", id, err)
	}
}
