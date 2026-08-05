// Package config loads Loom runtime settings from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is process-level Loom configuration (env-driven).
type Config struct {
	// Addr HTTP listen address.
	Addr string
	// DataDir file-backed stores.
	DataDir string
	// DatabaseURL Postgres DSN.
	DatabaseURL string
	// RedisURL redis://host:6379/0 for distributed quotas.
	RedisURL string
	// JWTSecret raw secret (min 16); empty generates an ephemeral development
	// secret and is rejected by production validation.
	JWTSecret string
	// JWTIssuer / JWTAudience.
	JWTKeyID    string
	JWTIssuer   string
	JWTAudience string
	// TenantClaim is a verified JWT claim copied into Identity.Attributes
	// under the standard tenant_id key when tenant enforcement is enabled.
	TenantClaim string
	// AuditJSONL optional path.
	AuditJSONL string
	// PGMaxOpenConns pool size (default 20).
	PGMaxOpenConns int
	// PGMaxIdleConns (default 5).
	PGMaxIdleConns int
	// FailClosedQuotas when Redis configured (default true).
	FailClosedQuotas bool
	// RequireDurable refuses to start with memory-only stores in production mode.
	RequireDurable bool
	// DisableDemoPrincipals skips seeding the publicly-known demo bearer tokens
	// (required together with RequireDurable by bootstrap).
	DisableDemoPrincipals bool
	// Env is LOOM_ENV (development|production). Production hardens defaults.
	Env string
	// AllowDemo explicitly permits demo principals outside development.
	AllowDemo bool
	// HTTPRateLimitPerMin edge rate limit per client IP (0 = disabled).
	HTTPRateLimitPerMin int
	// PolicyPath file for distributed policy JSON.
	PolicyPath string
	// PolicySyncInterval e.g. 5s; empty = 5s default in bootstrap.
	PolicySyncInterval time.Duration
	// TrustedTLSProxy means a deployment terminates TLS before Loom. It is
	// required explicitly before production plaintext listeners are allowed.
	TrustedTLSProxy bool
}

// Load reads LOOM_* environment variables with safe defaults.
func Load() Config {
	c := Config{
		Addr:                  env("LOOM_ADDR", ":8080"),
		DataDir:               os.Getenv("LOOM_DATA_DIR"),
		DatabaseURL:           os.Getenv("LOOM_DATABASE_URL"),
		RedisURL:              os.Getenv("LOOM_REDIS_URL"),
		JWTSecret:             os.Getenv("LOOM_JWT_SECRET"),
		JWTKeyID:              os.Getenv("LOOM_JWT_KEY_ID"),
		JWTIssuer:             os.Getenv("LOOM_JWT_ISSUER"),
		JWTAudience:           os.Getenv("LOOM_JWT_AUDIENCE"),
		TenantClaim:           os.Getenv("LOOM_TENANT_CLAIM"),
		AuditJSONL:            os.Getenv("LOOM_AUDIT_JSONL"),
		PGMaxOpenConns:        envInt("LOOM_PG_MAX_OPEN", 20),
		PGMaxIdleConns:        envInt("LOOM_PG_MAX_IDLE", 5),
		FailClosedQuotas:      envBool("LOOM_QUOTA_FAIL_CLOSED", true),
		RequireDurable:        envBool("LOOM_REQUIRE_DURABLE", false),
		DisableDemoPrincipals: envBool("LOOM_DISABLE_DEMO_PRINCIPALS", false),
		Env:                   strings.ToLower(env("LOOM_ENV", "development")),
		AllowDemo:             envBool("LOOM_ALLOW_DEMO", false),
		HTTPRateLimitPerMin:   envInt("LOOM_HTTP_RATE_LIMIT", 0),
		PolicyPath:            os.Getenv("LOOM_POLICY_PATH"),
		PolicySyncInterval:    ParseDurationEnv("LOOM_POLICY_SYNC_INTERVAL", 5*time.Second),
		TrustedTLSProxy:       envBool("LOOM_TRUSTED_TLS_PROXY", false),
	}
	return c
}

// IsProduction reports whether Env is a production-like profile.
func (c Config) IsProduction() bool {
	switch c.Env {
	case "production", "prod", "staging":
		return true
	default:
		return false
	}
}

// Validate checks adversarial production constraints.
func (c Config) Validate() error {
	if c.RequireDurable {
		if c.DatabaseURL == "" && c.DataDir == "" {
			return fmt.Errorf("LOOM_REQUIRE_DURABLE set but no LOOM_DATABASE_URL or LOOM_DATA_DIR")
		}
		if c.RedisURL == "" {
			return fmt.Errorf("LOOM_REQUIRE_DURABLE requires LOOM_REDIS_URL for distributed quota state")
		}
		if c.JWTSecret == "" {
			return fmt.Errorf("LOOM_REQUIRE_DURABLE requires LOOM_JWT_SECRET")
		}
	}
	if c.JWTSecret != "" && len(c.JWTSecret) < 16 {
		return fmt.Errorf("LOOM_JWT_SECRET too short (min 16 bytes)")
	}
	if strings.HasPrefix(c.JWTSecret, "dev-only") {
		return fmt.Errorf("refusing dev JWT secret when explicitly set as LOOM_JWT_SECRET value starting with dev-only")
	}
	if c.IsProduction() {
		if !c.DisableDemoPrincipals && !c.AllowDemo {
			return fmt.Errorf("LOOM_ENV=%s requires LOOM_DISABLE_DEMO_PRINCIPALS=true (or LOOM_ALLOW_DEMO=true for explicit demo)", c.Env)
		}
		if c.JWTSecret == "" {
			return fmt.Errorf("LOOM_ENV=%s requires LOOM_JWT_SECRET (min 16 bytes)", c.Env)
		}
		if c.JWTIssuer == "" || c.JWTAudience == "" {
			return fmt.Errorf("LOOM_ENV=%s requires LOOM_JWT_ISSUER and LOOM_JWT_AUDIENCE", c.Env)
		}
		if !c.RequireDurable {
			return fmt.Errorf("LOOM_ENV=%s requires LOOM_REQUIRE_DURABLE=true with LOOM_DATABASE_URL or LOOM_DATA_DIR", c.Env)
		}
	}
	return nil
}

// Durable reports whether a non-memory store is configured.
func (c Config) Durable() bool {
	return c.DatabaseURL != "" || c.DataDir != ""
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// ParseDurationEnv helper for future flags.
func ParseDurationEnv(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
