package app_test

import (
	"testing"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
)

func TestStagingValidatesDurabilityPerOperation(t *testing.T) {
	a, err := app.New(app.Config{
		Environment:      "staging",
		IdentityVerifier: identity.NewMemoryVerifier(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Register(&core.Operation{
		Name: "write", Effects: []core.Effect{core.EffectWrite},
	}, func(*core.ExecutionContext) (*core.Result, error) { return &core.Result{}, nil }); err == nil {
		t.Fatal("staging must reject side-effect operation without durable status")
	}
}
