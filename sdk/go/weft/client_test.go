package weft_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/internal/testtokens"
	weft "github.com/loreste/loom/sdk/go/weft"
)

func newTestClient(t *testing.T) *weft.Client {
	t.Helper()
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               testtokens.Demo(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return weft.New(p.Runtime)
}

func TestClientInvokeReachesGovernedRuntime(t *testing.T) {
	client := newTestClient(t)
	resp, err := client.Invoke(context.Background(), weft.StepCall{
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
		t.Fatalf("granted call denied: %+v", resp.Denial)
	}
}

// The SDK is a thin wrapper, so its contract is that it grants nothing of its
// own: an operation the principal lacks must still be denied through it.
func TestClientGrantsNoPrivilegeOfItsOwn(t *testing.T) {
	client := newTestClient(t)
	resp, err := client.Invoke(context.Background(), weft.StepCall{
		Operation:   "payment.capture",
		BearerToken: "alice-secret-token",
		Boundary:    "dev",
		Input:       map[string]any{"amount": 100},
	})
	if err == nil && resp.Allowed {
		t.Fatal("SDK allowed an operation the principal is not granted")
	}
}

func TestClientUnconfiguredFailsClosed(t *testing.T) {
	var nilClient *weft.Client
	if _, err := nilClient.Invoke(context.Background(), weft.StepCall{Operation: "document.read"}); err == nil {
		t.Fatal("nil client returned no error from Invoke")
	}
	if _, err := nilClient.BatchInvoke(context.Background(), nil, weft.BatchOptions{}); err == nil {
		t.Fatal("nil client returned no error from BatchInvoke")
	}
	// A zero-value client has no adapter and must not panic either.
	empty := &weft.Client{}
	if _, err := empty.Invoke(context.Background(), weft.StepCall{Operation: "document.read"}); err == nil {
		t.Fatal("zero-value client returned no error from Invoke")
	}
}

func TestClientBatchInvokeAppliesGovernance(t *testing.T) {
	client := newTestClient(t)
	result, err := client.BatchInvoke(context.Background(), []weft.StepCall{
		{
			WorkflowID: "wf-1", StepID: "s1", Operation: "document.read",
			BearerToken: "alice-secret-token", Boundary: "dev",
			Resource: &core.ResourceRef{Type: "document", ID: "1"},
			Input:    map[string]any{"id": "1"},
		},
		{
			WorkflowID: "wf-1", StepID: "s2", Operation: "payment.capture",
			BearerToken: "alice-secret-token", Boundary: "dev",
			Input: map[string]any{"amount": 100},
		},
	}, weft.BatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Responses) != 2 {
		t.Fatalf("batch returned %d responses, want 2", len(result.Responses))
	}
	if !result.Responses[0].Allowed {
		t.Fatalf("granted step denied: %+v", result.Responses[0].Denial)
	}
	if result.Responses[1].Allowed {
		t.Fatal("ungranted step allowed in batch")
	}
}
