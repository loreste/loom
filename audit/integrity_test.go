package audit_test

import (
	"context"
	"strings"
	"testing"

	"github.com/loreste/loom/audit"
)

func TestHashChainDetectsTamperingAndCheckpointVerifies(t *testing.T) {
	base := &audit.MemorySink{}
	chain := audit.NewHashChainSink(base, "")
	if err := chain.Write(context.Background(), audit.Event{ID: "one", Operation: "profile.read"}); err != nil {
		t.Fatal(err)
	}
	if err := chain.Write(context.Background(), audit.Event{ID: "two", Operation: "profile.update"}); err != nil {
		t.Fatal(err)
	}
	events := base.Snapshot()
	if err := audit.VerifyChain(events, ""); err != nil {
		t.Fatal(err)
	}
	signer, err := audit.NewHMACCheckpointSigner([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := audit.CreateCheckpoint(events, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyCheckpoint(events, checkpoint, signer); err != nil {
		t.Fatal(err)
	}

	events[1].Message = "tampered"
	if err := audit.VerifyCheckpoint(events, checkpoint, signer); err == nil {
		t.Fatal("expected tampered event to fail verification")
	}
}

func TestHashChainDoesNotAdvanceWhenSinkFails(t *testing.T) {
	sink := &failingSink{}
	chain := audit.NewHashChainSink(sink, "seed")
	if err := chain.Write(context.Background(), audit.Event{ID: "failed"}); err == nil {
		t.Fatal("expected sink failure")
	}
	if got := chain.PreviousHash(); got != "seed" {
		t.Fatalf("previous hash advanced after failed write: %q", got)
	}
}

type failingSink struct{}

func (*failingSink) Write(context.Context, audit.Event) error { return context.DeadlineExceeded }
