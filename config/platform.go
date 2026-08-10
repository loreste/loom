package config

import (
	"strings"

	"github.com/loreste/loom/bootstrap"
)

// PlatformConfig maps process environment configuration into bootstrap.Config
// so CLI serve, workers, and embed helpers share one wiring path.
func (c Config) PlatformConfig() bootstrap.Config {
	fc := c.FailClosedQuotas
	cfg := bootstrap.Config{
		DataDir:               c.DataDir,
		DatabaseURL:           c.DatabaseURL,
		RedisURL:              c.RedisURL,
		AuditJSONL:            c.AuditJSONL,
		JWTIssuer:             c.JWTIssuer,
		JWTAudience:           c.JWTAudience,
		JWTKeyID:              c.JWTKeyID,
		FailClosedQuotas:      &fc,
		PGMaxOpenConns:        c.PGMaxOpenConns,
		PGMaxIdleConns:        c.PGMaxIdleConns,
		PolicyPath:            c.PolicyPath,
		PolicySyncInterval:    c.PolicySyncInterval,
		RequireDurable:        c.RequireDurable,
		DisableDemoPrincipals: c.DisableDemoPrincipals,
	}
	if c.JWTSecret != "" {
		cfg.JWTSecret = []byte(c.JWTSecret)
	}
	if claim := strings.TrimSpace(c.TenantClaim); claim != "" {
		cfg.JWTClaimAttributes = map[string]string{claim: "tenant_id"}
	}
	if c.WebhookConfigured() {
		cfg.Webhook = bootstrap.WebhookConfig{
			URL:          c.WebhookURL,
			Secret:       c.WebhookSecret,
			KeyID:        c.WebhookKeyID,
			AllowHosts:   append([]string(nil), c.WebhookAllowHosts...),
			FailClosed:   c.WebhookFailClosed,
			AllowHTTP:    c.WebhookAllowHTTP,
			AllowPrivate: c.WebhookAllowPrivate,
			Timeout:      c.WebhookTimeout,
			Durable:      c.WebhookDurable,
			RunWorker:    c.WebhookRunWorker,
		}
		// Development may omit the secret only when not production-validated.
		// Platform still requires a secret unless AllowUnsigned is set.
		// Production Validate() forbids missing secret and nondurable webhooks.
		if c.WebhookSecret == "" && !c.IsProduction() {
			cfg.Webhook.AllowUnsigned = true
		}
	}
	if c.OIDCIssuer != "" {
		cfg.OIDC = bootstrap.OIDCConfig{
			Issuer:          c.OIDCIssuer,
			Audience:        c.OIDCAudience,
			Algorithms:      append([]string(nil), c.OIDCAlgorithms...),
			ClaimBoundary:   c.OIDCClaimBoundary,
			RequireBoundary: c.OIDCRequireBoundary,
		}
	}
	return cfg
}
