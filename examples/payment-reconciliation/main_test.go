package main

import (
	"context"
	"testing"

	"github.com/loreste/loom/core"
)

type fakeProvider struct {
	state string
	reads int
}

func (p *fakeProvider) CaptureState(context.Context, string) (string, error) {
	p.reads++
	return p.state, nil
}

func TestUnconfirmedReconciliationReadsProviderWithoutRerunningHandler(t *testing.T) {
	provider := &fakeProvider{state: "confirmed"}
	response := core.Response{
		Outcome: core.OutcomeExecutedUnconfirmed,
		Output:  map[string]any{"provider_reference": "provider-1"},
	}
	state, err := reconcileUnconfirmed(context.Background(), response, provider)
	if err != nil {
		t.Fatal(err)
	}
	if state != "reconciled" || provider.reads != 1 {
		t.Fatalf("state=%q reads=%d", state, provider.reads)
	}
}

func TestOrdinaryResultDoesNotQueryProvider(t *testing.T) {
	provider := &fakeProvider{state: "confirmed"}
	state, err := reconcileUnconfirmed(context.Background(), core.Response{Outcome: core.OutcomeAllowed}, provider)
	if err != nil || state != "not_unconfirmed" || provider.reads != 0 {
		t.Fatalf("state=%q err=%v reads=%d", state, err, provider.reads)
	}
}
