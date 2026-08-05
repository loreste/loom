package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/loreste/loom/core"
)

// CertPrincipal maps a client certificate identity to a Loom principal.
type CertPrincipal struct {
	// FingerprintSHA256 is hex-encoded SHA-256 of the raw DER cert (lowercase).
	FingerprintSHA256 string
	// SPIFFEID optional URI SAN match (spiffe://...).
	SPIFFEID string
	// CommonName optional CN match when fingerprint/SPIFFE not used.
	CommonName string

	ID           core.PrincipalID
	Type         string
	Boundary     core.BoundaryID
	Capabilities []string
	Attributes   map[string]string
}

// MTLSVerifier authenticates via client certificate material.
// Adapters must extract certs from TLS state; this verifier never trusts
// caller-supplied "I have mTLS" claims without the cert digest/SPIFFE.
//
// Credentials:
//   - Scheme: "mtls"
//   - Token: SHA-256 hex fingerprint of leaf cert DER (preferred), OR
//   - Claims["spiffe_id"], Claims["fingerprint"] as alternatives
//   - Claims may also carry "cn" when registered by CN (discouraged).
type MTLSVerifier struct {
	mu            sync.RWMutex
	byFingerprint map[string]CertPrincipal
	bySPIFFE      map[string]CertPrincipal
	byCN          map[string]CertPrincipal
	// AllowCN enables CommonName matching (default false — CN is weak).
	AllowCN bool
}

// NewMTLSVerifier returns an empty mTLS verifier (deny all until Register).
func NewMTLSVerifier() *MTLSVerifier {
	return &MTLSVerifier{
		byFingerprint: make(map[string]CertPrincipal),
		bySPIFFE:      make(map[string]CertPrincipal),
		byCN:          make(map[string]CertPrincipal),
	}
}

// Register adds a certificate principal mapping.
func (v *MTLSVerifier) Register(p CertPrincipal) error {
	if v == nil {
		return fmt.Errorf("%w: nil verifier", core.ErrInvalidArgument)
	}
	if p.ID == "" {
		return fmt.Errorf("%w: principal id required", core.ErrInvalidArgument)
	}
	if p.FingerprintSHA256 == "" && p.SPIFFEID == "" && p.CommonName == "" {
		return fmt.Errorf("%w: fingerprint, spiffe, or cn required", core.ErrInvalidArgument)
	}
	if p.Type == "" {
		p.Type = "service"
	}
	p.FingerprintSHA256 = strings.ToLower(strings.TrimSpace(p.FingerprintSHA256))
	p.Capabilities = append([]string(nil), p.Capabilities...)

	v.mu.Lock()
	defer v.mu.Unlock()
	if p.FingerprintSHA256 != "" {
		v.byFingerprint[p.FingerprintSHA256] = p
	}
	if p.SPIFFEID != "" {
		v.bySPIFFE[p.SPIFFEID] = p
	}
	if p.CommonName != "" {
		v.byCN[p.CommonName] = p
	}
	return nil
}

// ClaimPeerVerified is set only by adapters that extracted a real TLS peer cert
// (HTTP mTLS). Callers cannot forge mTLS by supplying scheme=mtls + fingerprint.
const ClaimPeerVerified = "peer_verified"

// Authenticate implements Verifier.
func (v *MTLSVerifier) Authenticate(ctx context.Context, creds core.Credentials) (core.Identity, error) {
	if err := ctx.Err(); err != nil {
		return core.Identity{}, err
	}
	if v == nil {
		return core.Identity{}, fmt.Errorf("identity: mtls verifier not configured")
	}
	if strings.ToLower(creds.Scheme) != "mtls" {
		return core.Identity{}, fmt.Errorf("identity: not mtls scheme")
	}
	// Fail closed: fingerprint knowledge alone is not proof of possession.
	// Only CredentialsFromCertificate (or equivalent TLS adapter) sets this claim.
	if creds.Claims == nil || creds.Claims[ClaimPeerVerified] != "1" {
		return core.Identity{}, fmt.Errorf("identity: mtls requires verified peer certificate")
	}

	fp := strings.ToLower(strings.TrimSpace(creds.Token))
	if fp == "" && creds.Claims != nil {
		fp = strings.ToLower(strings.TrimSpace(creds.Claims["fingerprint"]))
	}
	spiffe := ""
	cn := ""
	if creds.Claims != nil {
		spiffe = strings.TrimSpace(creds.Claims["spiffe_id"])
		cn = strings.TrimSpace(creds.Claims["cn"])
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	var p CertPrincipal
	var ok bool
	if fp != "" {
		p, ok = v.byFingerprint[fp]
	}
	if !ok && spiffe != "" {
		p, ok = v.bySPIFFE[spiffe]
	}
	if !ok && cn != "" && v.AllowCN {
		p, ok = v.byCN[cn]
	}
	if !ok {
		return core.Identity{}, fmt.Errorf("identity: mtls authentication failed")
	}

	attrs := map[string]string{}
	for k, val := range p.Attributes {
		attrs[k] = val
	}
	if fp != "" {
		attrs["cert_sha256"] = fp
	}
	if spiffe != "" {
		attrs["spiffe_id"] = spiffe
	}

	return core.Identity{
		ID:           p.ID,
		Type:         p.Type,
		Boundary:     p.Boundary,
		Attributes:   attrs,
		Capabilities: append([]string(nil), p.Capabilities...),
		AuthMethod:   "mtls",
	}, nil
}

// FingerprintSHA256 returns hex SHA-256 of cert DER.
func FingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// SPIFFEID extracts the first spiffe:// URI SAN, if any.
func SPIFFEID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, u := range cert.URIs {
		if u != nil && u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

// CredentialsFromCertificate builds mtls credentials from a leaf cert.
// Sets ClaimPeerVerified so the verifier accepts only TLS-proven peers.
func CredentialsFromCertificate(cert *x509.Certificate) core.Credentials {
	if cert == nil {
		return core.Credentials{Scheme: "mtls"}
	}
	claims := map[string]string{
		ClaimPeerVerified: "1",
	}
	if id := SPIFFEID(cert); id != "" {
		claims["spiffe_id"] = id
	}
	if cert.Subject.CommonName != "" {
		claims["cn"] = cert.Subject.CommonName
	}
	return core.Credentials{
		Scheme: "mtls",
		Token:  FingerprintSHA256(cert),
		Claims: claims,
	}
}
