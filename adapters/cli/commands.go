package cli

// DocumentedCommands is the machine-readable inventory of implemented CLI
// commands. Tests compare this against help text and release-manifest.json.
func DocumentedCommands() map[string][]string {
	return map[string][]string{
		"": {
			"exec", "serve", "mint-jwt", "approve", "recovery-worker", "webhook-worker",
			"recovery", "execution", "audit", "policy", "migrate", "version",
		},
		"recovery":  {"list", "requeue", "dead-letter"},
		"execution": {"get"},
		"audit": {
			"head", "verify", "export", "checkpoint", "verify-checkpoint", "rotate",
		},
		"policy": {"lint", "test", "diff", "explain", "simulate"},
	}
}
