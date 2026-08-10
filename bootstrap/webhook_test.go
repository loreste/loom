package bootstrap_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/internal/testtokens"
)

func TestPlatformWiresWebhookIntoAuditPipeline(t *testing.T) {
	var hits atomic.Int64
	// Cleartext loopback is development-only (AllowHTTP+AllowPrivate).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Header.Get("X-Loom-Signature") == "" {
			t.Error("missing signature header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Inline nondurable path (no Postgres): Write still delivers for demos.
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               testtokens.Demo(),
		Webhook: bootstrap.WebhookConfig{
			URL:          srv.URL,
			Secret:       "wiring-secret",
			KeyID:        "wire-1",
			AllowHTTP:    true,
			AllowPrivate: true,
			Timeout:      2 * time.Second,
			Durable:      false,
		},
	})
	if err != nil {
		t.Fatalf("NewPlatform: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	token := p.DemoTokens["user:alice"]
	if token == "" {
		t.Fatal("missing demo token")
	}
	resp := p.Runtime.Execute(context.Background(), core.Request{
		Operation:        "document.read",
		OperationVersion: "1",
		Boundary:         "dev",
		Credentials:      core.Credentials{Scheme: "bearer", Token: token},
		Resource:         &core.ResourceRef{Type: "document", ID: "1"},
		Input:            map[string]any{"id": "1"},
	})
	if !resp.Allowed {
		t.Fatalf("expected allow: %+v", resp.Denial)
	}
	if hits.Load() == 0 {
		t.Fatal("webhook sink was not invoked for an audited execution")
	}
}

func TestPlatformDurableWebhookWithoutPostgresFailsClosed(t *testing.T) {
	// Durable must never silently degrade to inline delivery when no outbox exists.
	_, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               testtokens.Demo(),
		Webhook: bootstrap.WebhookConfig{
			URL: "https://hooks.example.test/loom", Secret: "s", Durable: true,
		},
	})
	if err == nil {
		t.Fatal("durable webhook without PostgreSQL outbox must fail closed")
	}
}

func TestPlatformRequireDurableRejectsInlineWebhook(t *testing.T) {
	dir := t.TempDir()
	_, err := bootstrap.NewPlatform(bootstrap.Config{
		DataDir: dir, RedisURL: "redis://127.0.0.1:1",
		JWTSecret: []byte("configured-test-secret-1234"),
		RequireDurable: true, DisableDemoPrincipals: true,
		PolicySyncInterval: -1, DisableSeedPolicyPublish: true,
		Webhook: bootstrap.WebhookConfig{
			URL: "http://127.0.0.1:1/hook", Secret: "s",
			AllowHTTP: true, AllowPrivate: true, Durable: false,
		},
	})
	if err == nil {
		t.Fatal("RequireDurable must reject nondurable inline webhooks")
	}
}

func TestPlatformRejectsWebhookWithoutSecret(t *testing.T) {
	_, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		Webhook: bootstrap.WebhookConfig{
			URL:          "https://hooks.example.test/loom",
			AllowPrivate: false,
		},
	})
	if err == nil {
		t.Fatal("webhook without secret must fail closed at bootstrap")
	}
}

func TestPlatformRejectsPrivateWebhookByDefault(t *testing.T) {
	_, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		Webhook: bootstrap.WebhookConfig{
			URL:    "https://127.0.0.1/hook",
			Secret: "s",
		},
	})
	if err == nil {
		t.Fatal("private webhook destination must be rejected")
	}
}

