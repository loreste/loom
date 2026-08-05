// Command loom is the CLI entrypoint for the Loom universal runtime.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/loreste/loom/adapters/cli"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/config"
	"github.com/loreste/loom/tenancy"
)

// Filled at link time by scripts/build-release.sh / make build:
//
//	-ldflags "-X main.version=… -X main.commit=… -X main.date=…"
//
// Default matches VERSION file when not injected (dev builds).
var (
	version = "0.1.1"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	env := config.Load()
	if err := env.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	fc := env.FailClosedQuotas
	bcfg := bootstrap.Config{
		DataDir:               env.DataDir,
		DatabaseURL:           env.DatabaseURL,
		RedisURL:              env.RedisURL,
		JWTKeyID:              env.JWTKeyID,
		JWTIssuer:             env.JWTIssuer,
		JWTAudience:           env.JWTAudience,
		AuditJSONL:            env.AuditJSONL,
		PGMaxOpenConns:        env.PGMaxOpenConns,
		PGMaxIdleConns:        env.PGMaxIdleConns,
		FailClosedQuotas:      &fc,
		PolicyPath:            env.PolicyPath,
		PolicySyncInterval:    env.PolicySyncInterval,
		RequireDurable:        env.RequireDurable,
		DisableDemoPrincipals: env.DisableDemoPrincipals,
		DemoTokens: map[string]string{
			"user:alice":      os.Getenv("LOOM_DEMO_TOKEN_ALICE"),
			"user:bob":        os.Getenv("LOOM_DEMO_TOKEN_BOB"),
			"user:ops":        os.Getenv("LOOM_DEMO_TOKEN_OPS"),
			"user:approver":   os.Getenv("LOOM_DEMO_TOKEN_APPROVER"),
			"agent:assistant": os.Getenv("LOOM_DEMO_TOKEN_AGENT"),
		},
	}
	if env.TenantClaim != "" {
		resolver, err := tenancy.NewResolver("tenant_id")
		if err != nil {
			fmt.Fprintln(os.Stderr, "tenancy:", err)
			os.Exit(2)
		}
		bcfg.TenantResolver = resolver
		bcfg.JWTClaimAttributes = map[string]string{"tenant_id": env.TenantClaim}
	}
	if env.JWTSecret != "" {
		bcfg.JWTSecret = []byte(env.JWTSecret)
	}
	p, err := bootstrap.NewPlatform(bcfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(2)
	}
	defer func() { _ = p.Close() }()
	ad := cli.NewWithPlatform(p)
	ad.Version = fmt.Sprintf("%s (%s %s)", version, commit, date)
	os.Exit(ad.Run(context.Background(), os.Args[1:]))
}
