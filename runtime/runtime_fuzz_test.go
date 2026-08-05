package runtime_test

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
)

// FuzzExecute ensures arbitrary inputs never panic and never allow without grants.
func FuzzExecute(f *testing.F) {
	s := setupGranted(f)
	f.Add("document.read", "tok-alice", "dev", "document", "doc-1", "")
	f.Add("document.read", "", "dev", "document", "x", "x-loom-bypass")
	f.Add("payment.capture", "tok-alice", "prod", "payment", "p", "")
	f.Add("../evil", "tok-alice", "dev", "document", "1", "")
	f.Add("document.read", "tok-alice", "dev", "document", "1", "x-admin-override")

	f.Fuzz(func(t *testing.T, op, token, boundary, resType, resID, metaKey string) {
		input := map[string]any{"id": resID}
		md := map[string]string{}
		if metaKey != "" {
			md[metaKey] = "1"
		}
		req := core.Request{
			Operation:   op,
			Credentials: core.Credentials{Scheme: "bearer", Token: token},
			Boundary:    core.BoundaryID(boundary),
			Resource:    &core.ResourceRef{Type: resType, ID: resID},
			Input:       input,
			Metadata:    md,
		}
		resp := s.Runtime.Execute(context.Background(), req)
		// Invariant: allow only for alice + document.read + dev under this stack.
		if resp.Allowed {
			if token != "tok-alice" {
				t.Fatalf("allowed with bad token")
			}
			if op != "document.read" {
				t.Fatalf("allowed unexpected op %q", op)
			}
			if boundary != "dev" {
				t.Fatalf("allowed outside dev")
			}
			if resType != "document" {
				t.Fatalf("allowed unexpected resource type")
			}
		}
		if !resp.Allowed && resp.Denial == nil {
			t.Fatal("deny without denial struct")
		}
	})
}
