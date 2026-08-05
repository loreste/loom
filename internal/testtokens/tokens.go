// Package testtokens contains credentials used only by repository tests.
// Production bootstrap generates development credentials instead of embedding
// these values.
package testtokens

// Demo returns the fixture credentials expected by tests that exercise the
// development bootstrap profile.
func Demo() map[string]string {
	return map[string]string{
		"user:alice":      "alice-secret-token",
		"user:bob":        "bob-finance-token",
		"user:ops":        "ops-deploy-token",
		"user:approver":   "approver-admin-token",
		"agent:assistant": "agent-token-dev",
	}
}
