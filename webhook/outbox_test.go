package webhook_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/webhook"
)

func TestOutboxSinkEnqueuesWithoutHTTP(t *testing.T) {
	outbox := webhook.NewMemoryOutbox()
	sink, err := webhook.NewOutboxSink(outbox)
	if err != nil {
		t.Fatal(err)
	}
	if !sink.Durable() {
		t.Fatal("outbox sink must report durable")
	}
	if err := sink.Write(context.Background(), audit.Event{ID: "evt-1", Operation: "op", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), audit.Event{ID: "evt-1", Operation: "op", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	depth, _, err := outbox.Count(context.Background())
	if err != nil || depth != 1 {
		t.Fatalf("depth=%d err=%v, want 1", depth, err)
	}
}

func TestWorkerDeliversAndMarksComplete(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Header.Get("X-Loom-Signature") == "" {
			t.Error("missing signature")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport, err := webhook.NewSink(webhook.Config{
		URL:    srv.URL,
		Secret: "s",
		Destination: webhook.DestinationPolicy{
			AllowHTTP:    true,
			AllowPrivate: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	outbox := webhook.NewMemoryOutbox()
	if err := outbox.Enqueue(context.Background(), webhook.OutboxRecord{
		EventID: "evt-deliver",
		Event:   audit.Event{ID: "evt-deliver", Operation: "pay.capture", Decision: "allow"},
	}); err != nil {
		t.Fatal(err)
	}
	worker, err := webhook.NewWorker(webhook.WorkerConfig{
		Outbox: outbox, Deliverer: webhook.HTTPDeliverer{Sink: transport},
		Owner: "w1", Lease: time.Second, Poll: time.Millisecond,
		BackoffBase: time.Millisecond, BackoffMax: time.Second, DisableJitter: true, MaxAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.Delivered || hits.Load() != 1 {
		t.Fatalf("result=%+v err=%v hits=%d", result, err, hits.Load())
	}
	depth, _, _ := outbox.Count(context.Background())
	if depth != 0 {
		t.Fatalf("depth after deliver = %d", depth)
	}
}

func TestWorkerSchedulesRetryThenDeadLettersAndRequeues(t *testing.T) {
	failing := delivererFunc(func(context.Context, webhook.OutboxRecord) error {
		return errors.New("endpoint down")
	})

	outbox := webhook.NewMemoryOutbox()
	const id = "outbox-retry-1"
	if err := outbox.Enqueue(context.Background(), webhook.OutboxRecord{
		ID: id, EventID: "evt-retry", Event: audit.Event{ID: "evt-retry", Operation: "op"},
	}); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_000, 0)
	worker, err := webhook.NewWorker(webhook.WorkerConfig{
		Outbox: outbox, Deliverer: failing,
		Owner: "w1", Lease: time.Second, Poll: time.Millisecond,
		BackoffBase: time.Second, BackoffMax: 10 * time.Second, DisableJitter: true, MaxAttempts: 2,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil || !result.Scheduled {
		t.Fatalf("schedule: %+v err=%v", result, err)
	}

	clock = clock.Add(2 * time.Second)
	result, err = worker.ProcessOne(context.Background())
	if err != nil || !result.DeadLettered {
		t.Fatalf("dead letter: %+v err=%v", result, err)
	}

	got, err := outbox.Requeue(context.Background(), id, "operator approved")
	if err != nil || got.State != webhook.StatePending {
		t.Fatalf("requeue = %+v err=%v", got, err)
	}
	depth, _, _ := outbox.Count(context.Background())
	if depth != 1 {
		t.Fatalf("depth after requeue = %d", depth)
	}
}

func TestDeliveryFailureDoesNotFailOutboxWrite(t *testing.T) {
	outbox := webhook.NewMemoryOutbox()
	sink, _ := webhook.NewOutboxSink(outbox)
	if err := sink.Write(context.Background(), audit.Event{ID: "side-effect-done", Operation: "pay"}); err != nil {
		t.Fatal(err)
	}
	depth, _, _ := outbox.Count(context.Background())
	if depth != 1 {
		t.Fatalf("depth=%d", depth)
	}
}

func TestWorkerDoesNotReclaimDelivered(t *testing.T) {
	outbox := webhook.NewMemoryOutbox()
	_ = outbox.Enqueue(context.Background(), webhook.OutboxRecord{
		EventID: "evt-ok", Event: audit.Event{ID: "evt-ok", Operation: "op"},
	})
	var hits atomic.Int64
	worker, _ := webhook.NewWorker(webhook.WorkerConfig{
		Outbox: outbox,
		Deliverer: delivererFunc(func(context.Context, webhook.OutboxRecord) error {
			hits.Add(1)
			return nil
		}),
		Owner: "w1", Lease: time.Second, Poll: time.Millisecond, MaxAttempts: 3, DisableJitter: true,
	})
	if _, err := worker.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := outbox.Claim(context.Background(), "w2", time.Second); ok {
		t.Fatal("delivered record must not be reclaimed")
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

type delivererFunc func(context.Context, webhook.OutboxRecord) error

func (f delivererFunc) Deliver(ctx context.Context, rec webhook.OutboxRecord) error {
	return f(ctx, rec)
}
