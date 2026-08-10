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
	// ByScheme maps scheme → verifier (e.g. "bearer", "jwt", "oidc", "mtls").
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
	// jwt/oidc often arrive as bearer — try scheme-specific first, then fall through.
	if v, ok := m.ByScheme[scheme]; ok && v != nil {
		id, err := v.Authenticate(ctx, creds)
		if err == nil {
			return id, nil
		}
		// For bearer: fall through to jwt then oidc if configured.
		if scheme == "bearer" {
			if id2, ok2 := m.tryBearerAlternates(ctx, creds); ok2 {
				return id2, nil
			}
		}
		// Preserve the primary scheme error when alternates also fail (fail closed,
		// no algorithm confusion via error rewriting).
		return core.Identity{}, err
	}
	if scheme == "bearer" {
		if id, ok := m.tryBearerAlternates(ctx, creds); ok {
			return id, nil
		}
	}
	if m.Fallback != nil {
		return m.Fallback.Authenticate(ctx, creds)
	}
	return core.Identity{}, fmt.Errorf("identity: no verifier for scheme %q", scheme)
}

// tryBearerAlternates tries jwt then oidc verifiers for a bearer credential.
// Order preserves existing HMAC/JWT behavior and only reaches OIDC after JWT fails.
func (m *MultiVerifier) tryBearerAlternates(ctx context.Context, creds core.Credentials) (core.Identity, bool) {
	for _, name := range []string{"jwt", "oidc"} {
		v, ok := m.ByScheme[name]
		if !ok || v == nil {
			continue
		}
		alt := creds
		alt.Scheme = name
		id, err := v.Authenticate(ctx, alt)
		if err == nil {
			return id, true
		}
	}
	return core.Identity{}, false
}
