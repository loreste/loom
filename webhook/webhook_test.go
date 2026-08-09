package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/loreste/loom/audit"
)

func TestSinkDeliversEvent(t *testing.T) {
	var received atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received.Store(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewSink(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.Event{Operation: "test.op", Decision: "allow"}
	if err := sink.Write(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	raw := received.Load().([]byte)
	var got audit.Event
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Operation != "test.op" {
		t.Fatalf("got operation %q, want test.op", got.Operation)
	}
}

func TestSinkHMACSignature(t *testing.T) {
	secret := "test-secret"
	var sig atomic.Value
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig.Store(r.Header.Get("X-Loom-Signature"))
		b, _ := io.ReadAll(r.Body)
		body.Store(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewSink(Config{URL: srv.URL, Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), audit.Event{Operation: "signed.op"}); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body.Load().([]byte))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig.Load().(string) != want {
		t.Fatalf("signature mismatch: got %q, want %q", sig.Load(), want)
	}
}

func TestSinkFilterSkips(t *testing.T) {
	calls := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewSink(Config{
		URL:    srv.URL,
		Filter: func(ev audit.Event) bool { return ev.Decision == "deny" },
	})
	if err != nil {
		t.Fatal(err)
	}
	// allow event should be filtered
	sink.Write(context.Background(), audit.Event{Decision: "allow"})
	// deny event should be delivered
	sink.Write(context.Background(), audit.Event{Decision: "deny"})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 delivery, got %d", calls)
	}
}

func TestSinkFailOpenByDefault(t *testing.T) {
	sink, err := NewSink(Config{URL: "http://127.0.0.1:1"}) // connection refused
	if err != nil {
		t.Fatal(err)
	}
	// Should not return error (fail-open)
	if err := sink.Write(context.Background(), audit.Event{}); err != nil {
		t.Fatalf("fail-open sink returned error: %v", err)
	}
}

func TestSinkFailClosed(t *testing.T) {
	sink, err := NewSink(Config{URL: "http://127.0.0.1:1", FailClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), audit.Event{}); err == nil {
		t.Fatal("fail-closed sink should return error on connection failure")
	}
}

func TestSinkNotDurable(t *testing.T) {
	sink, _ := NewSink(Config{URL: "http://example.com"})
	if sink.Durable() {
		t.Fatal("webhook sink should not be durable")
	}
}

func TestNewSinkRequiresURL(t *testing.T) {
	_, err := NewSink(Config{})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}
