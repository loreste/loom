package identity_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
)

func TestJWTHappyPath(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, err := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets:  map[string][]byte{"": secret},
		Issuer:   "loom-test",
		Audience: "loom-api",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := identity.MintHS256(secret, "", map[string]any{
		"sub":          "user:alice",
		"iss":          "loom-test",
		"aud":          "loom-api",
		"exp":          now.Add(time.Hour).Unix(),
		"iat":          now.Unix(),
		"boundary":     "dev",
		"typ":          "user",
		"capabilities": []string{"document.read", "payment.capture"},
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Authenticate(context.Background(), core.Credentials{Scheme: "bearer", Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "user:alice" || id.Boundary != "dev" {
		t.Fatalf("%+v", id)
	}
	if len(id.Capabilities) != 2 {
		t.Fatalf("caps: %v", id.Capabilities)
	}
	if id.AuthMethod != "jwt" {
		t.Fatal(id.AuthMethod)
	}
}

func TestJWTMapsConfiguredAttributes(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, err := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets:         map[string][]byte{"": secret},
		ClaimAttributes: map[string]string{"tenant_id": "tid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := identity.MintHS256(secret, "", map[string]any{
		"sub": "user:tenant-a",
		"exp": time.Now().Add(time.Hour).Unix(),
		"tid": "tenant-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Authenticate(context.Background(), core.Credentials{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if id.Attributes["tenant_id"] != "tenant-a" {
		t.Fatalf("tenant claim was not mapped: %#v", id.Attributes)
	}
}

func TestJWTRejectsAlgNone(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, err := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets: map[string][]byte{"": secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	// craft unsigned-looking token with alg none
	// header {"alg":"none","typ":"JWT"}
	hdr := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	payload := "eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0"
	tok := hdr + "." + payload + "."
	_, err = v.Authenticate(context.Background(), core.Credentials{Token: tok})
	if err == nil {
		t.Fatal("alg none must fail")
	}
}

func TestJWTRejectsExpired(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, err := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets: map[string][]byte{"": secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := identity.MintHS256(secret, "", map[string]any{
		"sub": "user:alice",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	_, err = v.Authenticate(context.Background(), core.Credentials{Token: tok})
	if err == nil {
		t.Fatal("expired must fail")
	}
}

func TestJWTRejectsWrongIssuer(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, err := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets: map[string][]byte{"": secret},
		Issuer:  "expected",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := identity.MintHS256(secret, "", map[string]any{
		"sub": "user:alice",
		"iss": "evil",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	_, err = v.Authenticate(context.Background(), core.Credentials{Token: tok})
	if err == nil {
		t.Fatal("wrong iss must fail")
	}
}

func TestJWTRejectsMissingExp(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, _ := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets: map[string][]byte{"": secret},
	})
	tok, _ := identity.MintHS256(secret, "", map[string]any{
		"sub": "user:alice",
	})
	_, err := v.Authenticate(context.Background(), core.Credentials{Token: tok})
	if err == nil {
		t.Fatal("missing exp must fail")
	}
}

func TestJWTRejectsTamperedPayload(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v, _ := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets: map[string][]byte{"": secret},
	})
	tok, _ := identity.MintHS256(secret, "", map[string]any{
		"sub": "user:alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	parts := strings.Split(tok, ".")
	// flip a bit in payload section
	b := []byte(parts[1])
	b[len(b)/2] ^= 0x1
	parts[1] = string(b)
	_, err := v.Authenticate(context.Background(), core.Credentials{Token: strings.Join(parts, ".")})
	if err == nil {
		t.Fatal("tamper must fail")
	}
}

func TestJWTRejectsShortSecretConfig(t *testing.T) {
	_, err := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets: map[string][]byte{"": []byte("short")},
	})
	if err == nil {
		t.Fatal("short secret must reject")
	}
}

func TestMultiVerifierBearerThenJWT(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	mem := identity.NewMemoryVerifier()
	_ = mem.Register(identity.StaticPrincipal{ID: "user:static", Token: "static-tok", Boundary: "dev"})
	jwt, _ := identity.NewJWTVerifier(identity.JWTConfig{
		Secrets: map[string][]byte{"": secret},
	})
	multi := identity.NewMultiVerifier(map[string]identity.Verifier{
		"bearer": mem,
		"jwt":    jwt,
	})
	// static
	id, err := multi.Authenticate(context.Background(), core.Credentials{Token: "static-tok"})
	if err != nil || id.ID != "user:static" {
		t.Fatalf("%v %+v", err, id)
	}
	// jwt via bearer scheme
	tok, _ := identity.MintHS256(secret, "", map[string]any{
		"sub": "user:jwt",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	id, err = multi.Authenticate(context.Background(), core.Credentials{Scheme: "bearer", Token: tok})
	if err != nil || id.ID != "user:jwt" {
		t.Fatalf("%v %+v", err, id)
	}
}

func TestMTLSFingerprint(t *testing.T) {
	v := identity.NewMTLSVerifier()
	fp := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	_ = v.Register(identity.CertPrincipal{
		FingerprintSHA256: fp,
		ID:                "svc:payments",
		Boundary:          "prod",
		Capabilities:      []string{"payment.capture"},
	})
	id, err := v.Authenticate(context.Background(), core.Credentials{
		Scheme: "mtls",
		Token:  fp,
		Claims: map[string]string{identity.ClaimPeerVerified: "1"},
	})
	if err != nil || id.ID != "svc:payments" {
		t.Fatalf("%v %+v", err, id)
	}
	// Fingerprint alone (no peer_verified) must fail.
	_, err = v.Authenticate(context.Background(), core.Credentials{
		Scheme: "mtls",
		Token:  fp,
	})
	if err == nil {
		t.Fatal("mtls without peer_verified must fail")
	}
	_, err = v.Authenticate(context.Background(), core.Credentials{
		Scheme: "mtls",
		Token:  "deadbeef",
		Claims: map[string]string{identity.ClaimPeerVerified: "1"},
	})
	if err == nil {
		t.Fatal("unknown cert must fail")
	}
}
