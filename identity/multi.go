package identity

import (
	"context"
	"fmt"
	"strings"

	"github.com/loreste/loom/core"
)

// MultiVerifier dispatches by credential scheme.
// Unknown schemes fail closed. Empty scheme defaults to "bearer".
type MultiVerifier struct {
	// ByScheme maps scheme → verifier (e.g. "bearer", "jwt", "mtls").
	ByScheme map[string]Verifier
	// Fallback tried when scheme-specific missing (optional).
	Fallback Verifier
}

// NewMultiVerifier builds a multi-scheme verifier.
func NewMultiVerifier(byScheme map[string]Verifier) *MultiVerifier {
	m := make(map[string]Verifier, len(byScheme))
	for k, v := range byScheme {
		if v != nil {
			m[strings.ToLower(k)] = v
		}
	}
	return &MultiVerifier{ByScheme: m}
}

// Authenticate routes by scheme.
func (m *MultiVerifier) Authenticate(ctx context.Context, creds core.Credentials) (core.Identity, error) {
	if m == nil {
		return core.Identity{}, fmt.Errorf("identity: multi verifier not configured")
	}
	scheme := strings.ToLower(strings.TrimSpace(creds.Scheme))
	if scheme == "" {
		scheme = "bearer"
	}
	// jwt often arrives as bearer — if bearer missing, try jwt verifier with same token
	if v, ok := m.ByScheme[scheme]; ok && v != nil {
		id, err := v.Authenticate(ctx, creds)
		if err == nil {
			return id, nil
		}
		// For bearer: fall through to jwt if configured (token may be JWT)
		if scheme == "bearer" {
			if jv, jok := m.ByScheme["jwt"]; jok && jv != nil {
				jc := creds
				jc.Scheme = "jwt"
				if id2, err2 := jv.Authenticate(ctx, jc); err2 == nil {
					return id2, nil
				}
			}
		}
		return core.Identity{}, err
	}
	if scheme == "bearer" {
		if jv, ok := m.ByScheme["jwt"]; ok && jv != nil {
			jc := creds
			jc.Scheme = "jwt"
			return jv.Authenticate(ctx, jc)
		}
	}
	if m.Fallback != nil {
		return m.Fallback.Authenticate(ctx, creds)
	}
	return core.Identity{}, fmt.Errorf("identity: no verifier for scheme %q", scheme)
}
