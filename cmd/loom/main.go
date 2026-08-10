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
// Development builds report dev; release builds receive the exact VERSION
// value through ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	env := config.Load()
	if err := env.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	// Single wiring path: env → PlatformConfig → NewPlatform.
	bcfg := env.PlatformConfig()
	bcfg.DemoTokens = map[string]string{
		"user:alice":      os.Getenv("LOOM_DEMO_TOKEN_ALICE"),
		"user:bob":        os.Getenv("LOOM_DEMO_TOKEN_BOB"),
		"user:ops":        os.Getenv("LOOM_DEMO_TOKEN_OPS"),
		"user:approver":   os.Getenv("LOOM_DEMO_TOKEN_APPROVER"),
		"agent:assistant": os.Getenv("LOOM_DEMO_TOKEN_AGENT"),
	}
	if env.TenantClaim != "" {
		resolver, err := tenancy.NewResolver("tenant_id")
		if err != nil {
			fmt.Fprintln(os.Stderr, "tenancy:", err)
			os.Exit(2)
		}
		bcfg.TenantResolver = resolver
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
