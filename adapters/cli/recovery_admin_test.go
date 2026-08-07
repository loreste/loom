package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestRecoveryAdminListCallsGovernedExecuteEndpoint(t *testing.T) {
	var received map[string]any
	var out, errOut bytes.Buffer
	a := New(nil)
	a.Out = &out
	a.Err = &errOut
	a.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer operator-token" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"allowed":true,"output":{"count":0}}`)),
		}, nil
	})}
	if got := a.runRecoveryAdmin(context.Background(), "list", []string{"--url=https://loom.example", "--token=operator-token", "--boundary=ops"}); got != 0 {
		t.Fatalf("runRecoveryAdmin() = %d, stderr=%s", got, errOut.String())
	}
	if received["operation"] != "recovery.list" || received["boundary"] != "ops" {
		t.Fatalf("request = %#v", received)
	}
	if !strings.Contains(out.String(), `"allowed": true`) {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRecoveryAdminMutationRequiresApprovalAndIdempotency(t *testing.T) {
	var out, errOut bytes.Buffer
	a := New(nil)
	a.Out = &out
	a.Err = &errOut
	if got := a.runRecoveryAdmin(context.Background(), "requeue", []string{"--url=https://loom.example", "--token=operator-token", "--boundary=ops", "--execution-id=exec-1"}); got == 0 {
		t.Fatal("mutation without approval/idempotency unexpectedly succeeded")
	}
}
