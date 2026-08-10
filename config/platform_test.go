package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/loreste/loom/config"
)

func TestPlatformConfigWiresWebhookAndPolicy(t *testing.T) {
	t.Setenv("LOOM_ENV", "development")
	t.Setenv("LOOM_DATA_DIR", t.TempDir())
	t.Setenv("LOOM_POLICY_PATH", "/etc/loom/policy.json")
	t.Setenv("LOOM_WEBHOOK_URL", "https://hooks.example.test/loom")
	t.Setenv("LOOM_WEBHOOK_SECRET", "webhook-secret-at-least-16")
	t.Setenv("LOOM_WEBHOOK_KEY_ID", "k1")
	t.Setenv("LOOM_WEBHOOK_ALLOW_HOSTS", "hooks.example.test,alt.example.test")
	t.Setenv("LOOM_TENANT_CLAIM", "tid")
	t.Setenv("LOOM_JWT_SECRET", "configured-test-secret-1234")
	t.Setenv("LOOM_JWT_ISSUER", "https://issuer.example")
	t.Setenv("LOOM_JWT_AUDIENCE", "loom")

	c := config.Load()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.PlatformConfig()
	if p.PolicyPath != "/etc/loom/policy.json" {
		t.Fatalf("PolicyPath = %q", p.PolicyPath)
	}
	if p.Webhook.URL != "https://hooks.example.test/loom" || p.Webhook.Secret == "" || p.Webhook.KeyID != "k1" {
		t.Fatalf("webhook = %+v", p.Webhook)
	}
	if len(p.Webhook.AllowHosts) != 2 {
		t.Fatalf("AllowHosts = %v", p.Webhook.AllowHosts)
	}
	if p.JWTClaimAttributes["tid"] != "tenant_id" {
		t.Fatalf("JWTClaimAttributes = %#v", p.JWTClaimAttributes)
	}
	if string(p.JWTSecret) != "configured-test-secret-1234" {
		t.Fatalf("JWTSecret not mapped")
	}
}

func TestProductionRejectsUnsafeWebhook(t *testing.T) {
	t.Setenv("LOOM_ENV", "production")
	t.Setenv("LOOM_REQUIRE_DURABLE", "true")
	t.Setenv("LOOM_DISABLE_DEMO_PRINCIPALS", "true")
	t.Setenv("LOOM_DATA_DIR", t.TempDir())
	t.Setenv("LOOM_REDIS_URL", "redis://127.0.0.1:6379/0")
	t.Setenv("LOOM_JWT_SECRET", "configured-test-secret-1234")
	t.Setenv("LOOM_JWT_ISSUER", "https://issuer.example")
	t.Setenv("LOOM_JWT_AUDIENCE", "loom")
	t.Setenv("LOOM_WEBHOOK_URL", "https://hooks.example.test/loom")
	t.Setenv("LOOM_WEBHOOK_SECRET", "")
	if err := config.Load().Validate(); err == nil {
		t.Fatal("production webhook without secret must fail")
	}
	t.Setenv("LOOM_WEBHOOK_SECRET", "webhook-secret-at-least-16")
	t.Setenv("LOOM_WEBHOOK_ALLOW_HTTP", "true")
	if err := config.Load().Validate(); err == nil {
		t.Fatal("production webhook AllowHTTP must fail")
	}
	t.Setenv("LOOM_WEBHOOK_ALLOW_HTTP", "false")
	t.Setenv("LOOM_WEBHOOK_ALLOW_PRIVATE", "true")
	if err := config.Load().Validate(); err == nil {
		t.Fatal("production webhook AllowPrivate must fail")
	}
}

func TestReleaseManifestMatchesPythonIdentity(t *testing.T) {
	root := findRepoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "release-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		SDKs []struct {
			Language     string `json:"language"`
			Distribution string `json:"distribution"`
			Published    bool   `json:"published"`
			BlockedName  string `json:"blocked_name"`
		} `json:"sdks"`
		CLICommands map[string][]string `json:"cli_commands"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sdk := range manifest.SDKs {
		if sdk.Language != "python" {
			continue
		}
		found = true
		if sdk.Distribution != "loreste-loom" {
			t.Fatalf("python distribution = %q", sdk.Distribution)
		}
		if sdk.BlockedName != "loom-sdk" {
			t.Fatalf("blocked_name = %q", sdk.BlockedName)
		}
		if sdk.Published {
			t.Fatal("python must not claim published until public install succeeds")
		}
	}
	if !found {
		t.Fatal("python sdk missing from release-manifest.json")
	}
	if len(manifest.CLICommands["top_level"]) == 0 {
		t.Fatal("cli_commands.top_level empty")
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "release-manifest.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("release-manifest.json not found from %s", wd)
	return ""
}
