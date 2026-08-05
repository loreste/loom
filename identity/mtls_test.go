package identity_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
)

func TestMTLSRejectsForgedFingerprintWithoutPeerVerified(t *testing.T) {
	v := identity.NewMTLSVerifier()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fp := identity.FingerprintSHA256(cert)
	if err := v.Register(identity.CertPrincipal{
		FingerprintSHA256: fp,
		ID:                "svc:test",
		Boundary:          "dev",
		Capabilities:      []string{"payment.capture"},
	}); err != nil {
		t.Fatal(err)
	}

	// Attacker knows fingerprint but has no peer cert binding.
	_, err = v.Authenticate(context.Background(), core.Credentials{
		Scheme: "mtls",
		Token:  fp,
	})
	if err == nil {
		t.Fatal("forged mtls without peer_verified must fail")
	}

	// Real TLS-extracted credentials work.
	creds := identity.CredentialsFromCertificate(cert)
	id, err := v.Authenticate(context.Background(), creds)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "svc:test" {
		t.Fatalf("%v", id)
	}
}
