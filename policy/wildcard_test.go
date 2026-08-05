package policy_test

import (
	"testing"

	"github.com/loreste/loom/policy"
)

func TestGlobalWildcardAllowRequiresExplicitScope(t *testing.T) {
	if err := policy.NewMemoryEngine().AddRule(policy.Rule{Operation: "*"}); err == nil {
		t.Fatal("unscoped wildcard allow must be rejected")
	}
	if err := policy.NewMemoryEngine().AddRule(policy.Rule{Operation: "*", Deny: true}); err != nil {
		t.Fatalf("global deny should remain available: %v", err)
	}
}
