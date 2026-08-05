package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/loreste/loom/core"
)

// JWTConfig configures HMAC-SHA256 JWT verification.
// Adversarial defaults:
//   - alg "none" and anything other than HS256 rejected
//   - exp required (fail closed if missing)
//   - nbf enforced when present
//   - iss/aud enforced when configured (non-empty)
//   - clock skew limited (default 30s)
type JWTConfig struct {
	// HS256 secrets keyed by kid (empty kid = default).
	// Raw secrets; never log.
	Secrets map[string][]byte
	// Issuer required claim when non-empty.
	Issuer string
	// Audience required claim when non-empty (string or array membership).
	Audience string
	// ClockSkew allowed for exp/nbf (default 30s).
	ClockSkew time.Duration
	// ClaimPrincipal is the JWT claim for principal ID (default "sub").
	ClaimPrincipal string
	// ClaimBoundary optional claim for home boundary (default "boundary").
	ClaimBoundary string
	// ClaimType default "typ" or "token_use"; fallback "user".
	ClaimType string
	// ClaimCapabilities claim name for string array of caps (default "capabilities").
	ClaimCapabilities string
	// ClaimAttributes maps trusted JWT claim names to Identity.Attributes keys.
	ClaimAttributes map[string]string
	// RequiredCapabilities if non-empty, token must include all (AND).
	RequiredCapabilities []string
	// MaxTokenBytes rejects oversized tokens (default 8KiB).
	MaxTokenBytes int
}

// JWTVerifier verifies HS256 JWTs into core.Identity.
type JWTVerifier struct {
	cfg   JWTConfig
	mu    sync.RWMutex
	nowFn func() time.Time
}

// NewJWTVerifier constructs a verifier. At least one secret required.
func NewJWTVerifier(cfg JWTConfig) (*JWTVerifier, error) {
	if len(cfg.Secrets) == 0 {
		return nil, fmt.Errorf("%w: jwt secrets required", core.ErrInvalidArgument)
	}
	for kid, sec := range cfg.Secrets {
		if len(sec) < 16 {
			return nil, fmt.Errorf("%w: secret for kid %q too short (min 16 bytes)", core.ErrInvalidArgument, kid)
		}
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.ClaimPrincipal == "" {
		cfg.ClaimPrincipal = "sub"
	}
	if cfg.ClaimBoundary == "" {
		cfg.ClaimBoundary = "boundary"
	}
	if cfg.ClaimType == "" {
		cfg.ClaimType = "typ"
	}
	if cfg.ClaimCapabilities == "" {
		cfg.ClaimCapabilities = "capabilities"
	}
	if cfg.MaxTokenBytes <= 0 {
		cfg.MaxTokenBytes = 8 << 10
	}
	return &JWTVerifier{cfg: cfg, nowFn: time.Now}, nil
}

// SetClock overrides time source (tests only).
func (v *JWTVerifier) SetClock(fn func() time.Time) {
	if v == nil || fn == nil {
		return
	}
	v.mu.Lock()
	v.nowFn = fn
	v.mu.Unlock()
}

// Authenticate implements Verifier for scheme "bearer" or "jwt".
func (v *JWTVerifier) Authenticate(ctx context.Context, creds core.Credentials) (core.Identity, error) {
	if err := ctx.Err(); err != nil {
		return core.Identity{}, err
	}
	if v == nil {
		return core.Identity{}, fmt.Errorf("identity: jwt verifier not configured")
	}
	scheme := strings.ToLower(creds.Scheme)
	if scheme == "" {
		scheme = "bearer"
	}
	if scheme != "bearer" && scheme != "jwt" {
		return core.Identity{}, fmt.Errorf("identity: unsupported scheme %q for jwt", creds.Scheme)
	}
	token := strings.TrimSpace(creds.Token)
	if token == "" {
		return core.Identity{}, fmt.Errorf("identity: empty jwt")
	}
	if len(token) > v.cfg.MaxTokenBytes {
		return core.Identity{}, fmt.Errorf("identity: jwt too large")
	}

	claims, err := v.verifyHS256(token)
	if err != nil {
		// uniform failure message — no oracle on which check failed beyond generic
		return core.Identity{}, fmt.Errorf("identity: jwt authentication failed")
	}

	sub, _ := claimString(claims, v.cfg.ClaimPrincipal)
	if sub == "" {
		return core.Identity{}, fmt.Errorf("identity: jwt authentication failed")
	}
	boundary, _ := claimString(claims, v.cfg.ClaimBoundary)
	typ, _ := claimString(claims, v.cfg.ClaimType)
	if typ == "" {
		typ = "user"
	}
	caps := claimStringSlice(claims, v.cfg.ClaimCapabilities)
	for _, req := range v.cfg.RequiredCapabilities {
		if !containsFold(caps, req) {
			return core.Identity{}, fmt.Errorf("identity: jwt authentication failed")
		}
	}

	attrs := map[string]string{}
	if iss, ok := claimString(claims, "iss"); ok {
		attrs["iss"] = iss
	}
	if jti, ok := claimString(claims, "jti"); ok {
		attrs["jti"] = jti
	}
	for attribute, claimName := range v.cfg.ClaimAttributes {
		attribute = strings.TrimSpace(attribute)
		claimName = strings.TrimSpace(claimName)
		if attribute == "" || claimName == "" {
			continue
		}
		if value, ok := claimString(claims, claimName); ok {
			attrs[attribute] = value
		}
	}

	return core.Identity{
		ID:           core.PrincipalID(sub),
		Type:         typ,
		Boundary:     core.BoundaryID(boundary),
		Attributes:   attrs,
		Capabilities: caps,
		AuthMethod:   "jwt",
	}, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func (v *JWTVerifier) verifyHS256(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed")
	}
	hb, err := b64Decode(parts[0])
	if err != nil {
		return nil, err
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, err
	}
	// Absolute reject of alg confusion / none
	alg := strings.ToUpper(strings.TrimSpace(hdr.Alg))
	if alg != "HS256" {
		return nil, fmt.Errorf("alg")
	}

	v.mu.RLock()
	secrets := v.cfg.Secrets
	nowFn := v.nowFn
	v.mu.RUnlock()

	sec, ok := secrets[hdr.Kid]
	if !ok {
		// try default empty kid
		sec, ok = secrets[""]
	}
	if !ok || len(sec) == 0 {
		return nil, fmt.Errorf("kid")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, sec)
	_, _ = mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)
	sig, err := b64Decode(parts[2])
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(expected, sig) {
		return nil, fmt.Errorf("sig")
	}

	pb, err := b64Decode(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, err
	}

	now := nowFn()
	skew := v.cfg.ClockSkew

	// exp required
	exp, ok := claimTime(claims, "exp")
	if !ok {
		return nil, fmt.Errorf("exp required")
	}
	if now.After(exp.Add(skew)) {
		return nil, fmt.Errorf("expired")
	}
	if nbf, ok := claimTime(claims, "nbf"); ok {
		if now.Before(nbf.Add(-skew)) {
			return nil, fmt.Errorf("nbf")
		}
	}
	if iat, ok := claimTime(claims, "iat"); ok {
		// reject tokens from far future
		if iat.After(now.Add(skew + time.Minute)) {
			return nil, fmt.Errorf("iat")
		}
	}

	if v.cfg.Issuer != "" {
		iss, _ := claimString(claims, "iss")
		if iss != v.cfg.Issuer {
			return nil, fmt.Errorf("iss")
		}
	}
	if v.cfg.Audience != "" {
		if !audienceMatch(claims["aud"], v.cfg.Audience) {
			return nil, fmt.Errorf("aud")
		}
	}
	return claims, nil
}

// MintHS256 is a test/dev helper to issue tokens. Production issuers should be external.
func MintHS256(secret []byte, kid string, claims map[string]any) (string, error) {
	if len(secret) < 16 {
		return "", fmt.Errorf("%w: secret too short", core.ErrInvalidArgument)
	}
	hdr := jwtHeader{Alg: "HS256", Typ: "JWT", Kid: kid}
	hb, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hPart := b64Encode(hb)
	pPart := b64Encode(pb)
	signingInput := hPart + "." + pPart
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	sig := b64Encode(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

func b64Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64Decode(s string) ([]byte, error) {
	// accept raw or padded
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func claimString(m map[string]any, k string) (string, bool) {
	v, ok := m[k]
	if !ok || v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, t != ""
	default:
		return fmt.Sprint(t), true
	}
}

func claimStringSlice(m map[string]any, k string) []string {
	v, ok := m[k]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), t...)
	case string:
		if t == "" {
			return nil
		}
		// comma-separated
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	default:
		return nil
	}
}

func claimTime(m map[string]any, k string) (time.Time, bool) {
	v, ok := m[k]
	if !ok {
		return time.Time{}, false
	}
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	case int64:
		return time.Unix(t, 0), true
	case int:
		return time.Unix(int64(t), 0), true
	default:
		return time.Time{}, false
	}
}

func audienceMatch(aud any, want string) bool {
	switch t := aud.(type) {
	case string:
		return t == want
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range t {
			if s == want {
				return true
			}
		}
	}
	return false
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
