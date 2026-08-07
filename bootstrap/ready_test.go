package bootstrap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/internal/testtokens"
)

// A platform with no durable backends has no built-in probes, so an
// application-supplied check is the only thing standing between an unready
// dependency and a passing /readyz.
func TestPlatformReadyRunsApplicationChecks(t *testing.T) {
	failing := errors.New("verifier has not completed discovery")
	ready := false
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		DemoTokens: testtokens.Demo(),
		ReadyChecks: []func(context.Context) error{
			nil, // a nil entry must be skipped rather than panic
			func(context.Context) error {
				if !ready {
					return failing
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Ready == nil {
		t.Fatal("Ready is nil; the application check was not registered")
	}
	if err := p.Ready(context.Background()); !errors.Is(err, failing) {
		t.Fatalf("Ready() = %v, want the application check failure", err)
	}
	ready = true
	if err := p.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() = %v, want nil once the dependency is ready", err)
	}
}
