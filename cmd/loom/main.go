// Command loom is the CLI entrypoint for the Loom universal runtime.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/loreste/loom/adapters/cli"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/config"
)

// Filled at link time by scripts/build-release.sh / make build:
//
//	-ldflags "-X main.version=… -X main.commit=… -X main.date=…"
//
// Default matches VERSION file when not injected (dev builds).
var (
	version = "0.1.0"
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
