package app_test

import (
	"testing"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/identity"
)

func TestStagingRequiresProductionSecurityState(t *testing.T) {
	if _, err := app.New(app.Config{
		Environment:      "staging",
		IdentityVerifier: identity.NewMemoryVerifier(),
	}); err == nil {
		t.Fatal("staging must reject process-local security state")
	}
}
