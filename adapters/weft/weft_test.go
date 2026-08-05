package weft_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/adapters/weft"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
)

func TestWeftInvokeDocumentRead(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ad := weft.New(p.Runtime)
	resp, err := ad.Invoke(context.Background(), weft.StepCall{
		WorkflowID:  "wf-1",
		StepID:      "read-doc",
		Operation:   "document.read",
		BearerToken: "alice-secret-token",
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Input:       map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
}

func TestWeftAllowlistBlocks(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true})
	t.Cleanup(func() { _ = p.Close() })
	ad := weft.New(p.Runtime)
	ad.AllowedOperations = map[string]struct{}{"document.read": {}}
	resp, _ := ad.Invoke(context.Background(), weft.StepCall{
		Operation:   "payment.capture",
		BearerToken: "bob-finance-token",
		Boundary:    "dev",
	})
	if resp.Allowed {
		t.Fatal("allowlist must block")
	}
}

func TestWeftBypassHeaderDenied(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1, DisableSeedPolicyPublish: true})
	t.Cleanup(func() { _ = p.Close() })
	ad := weft.New(p.Runtime)
	resp, _ := ad.Invoke(context.Background(), weft.StepCall{
		Operation:   "document.read",
		BearerToken: "alice-secret-token",
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "document", ID: "1"},
		Input:       map[string]any{"id": "1"},
		Metadata:    map[string]string{"x-loom-bypass": "1"},
	})
	if resp.Allowed {
		t.Fatal("bypass must deny")
	}
}
