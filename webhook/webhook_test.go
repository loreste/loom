package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/loreste/loom/audit"
)

func TestSinkDeliversSignedEnvelope(t *testing.T) {
	var received atomic.Value
	var headers atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received.Store(body)
		headers.Store(r.Header.Clone())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewSink(Config{
		URL:    srv.URL,
		Secret: "test-secret",
		KeyID:  "k1",
		Destination: DestinationPolicy{
			AllowPrivate: true,
			Resolver:     staticResolver(net.ParseIP("127.0.0.1")),
		},
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.Event{ID: "evt-1", Operation: "test.op", Decision: "allow"}
	if err := sink.Write(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	raw := received.Load().([]byte)
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Event.Operation != "test.op" || envelope.EventID != "evt-1" {
		t.Fatalf("envelope = %+v", envelope)
	}
	hdr := headers.Load().(http.Header)
	if _, err := VerifyEnvelope(raw, hdr, "test-secret", map[string]string{"k1": "test-secret"}, time.Unix(envelope.Timestamp, 0), time.Minute); err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
}

func TestSinkRejectsPrivateDestinationsByDefault(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/hook",
		"https://127.0.0.1/hook",
		"https://localhost/hook",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.5/hook",
		"https://192.168.1.1/hook",
		"https://[::1]/hook",
		"https://user:pass@example.com/hook",
		"https://example.com/hook#frag",
		"ftp://example.com/hook",
	} {
		_, err := NewSink(Config{URL: raw, Secret: "s", Destination: DestinationPolicy{
			Resolver: staticResolver(net.ParseIP("10.0.0.5")),
		}})
		if err == nil {
			t.Fatalf("destination %q must be rejected", raw)
		}
	}
}

func TestSinkAllowsPublicHTTPS(t *testing.T) {
	// Construction resolves DNS; use a fixed public IP via custom resolver and
	// a custom client so no real network I/O is required after validation.
	public := net.ParseIP("1.1.1.1")
	_, err := NewSink(Config{
		URL:    "https://hooks.example.test/loom",
		Secret: "s",
		Destination: DestinationPolicy{
			Resolver:   staticResolver(public),
			AllowHosts: []string{"hooks.example.test"},
		},
		HTTPClient: &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatalf("public https destination rejected: %v", err)
	}
}

func TestSinkAllowlistRejectsOtherHosts(t *testing.T) {
	_, err := NewSink(Config{
		URL:    "https://evil.example/hook",
		Secret: "s",
		Destination: DestinationPolicy{
			Resolver:   staticResolver(net.ParseIP("1.1.1.1")),
			AllowHosts: []string{"hooks.example.test"},
		},
	})
	if err == nil {
		t.Fatal("host outside allowlist must be rejected")
	}
}

func TestSinkRequiresSecretUnlessAllowUnsigned(t *testing.T) {
	_, err := NewSink(Config{
		URL: "https://hooks.example.test/loom",
		Destination: DestinationPolicy{
			Resolver: staticResolver(net.ParseIP("1.1.1.1")),
		},
	})
	if err == nil {
		t.Fatal("missing secret must be rejected")
	}
	_, err = NewSink(Config{
		URL:           "https://hooks.example.test/loom",
		AllowUnsigned: true,
		Destination: DestinationPolicy{
			Resolver: staticResolver(net.ParseIP("1.1.1.1")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSinkFilterSkips(t *testing.T) {
	calls := int32(0)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewSink(Config{
		URL:    srv.URL,
		Secret: "s",
		Filter: func(ev audit.Event) bool { return ev.Decision == "deny" },
		Destination: DestinationPolicy{
			AllowPrivate: true,
			Resolver:     staticResolver(net.ParseIP("127.0.0.1")),
		},
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = sink.Write(context.Background(), audit.Event{Decision: "allow"})
	_ = sink.Write(context.Background(), audit.Event{Decision: "deny"})
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 delivery, got %d", calls)
	}
}

func TestSinkFailOpenByDefault(t *testing.T) {
	// Destination validates as private with AllowPrivate; dial fails.
	sink, err := NewSink(Config{
		URL:    "https://127.0.0.1:1/hook",
		Secret: "s",
		Destination: DestinationPolicy{
			AllowPrivate: true,
			Resolver:     staticResolver(net.ParseIP("127.0.0.1")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), audit.Event{}); err != nil {
		t.Fatalf("fail-open sink returned error: %v", err)
	}
}

func TestSinkFailClosed(t *testing.T) {
	sink, err := NewSink(Config{
		URL:        "https://127.0.0.1:1/hook",
		Secret:     "s",
		FailClosed: true,
		Destination: DestinationPolicy{
			AllowPrivate: true,
			Resolver:     staticResolver(net.ParseIP("127.0.0.1")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), audit.Event{}); err == nil {
		t.Fatal("fail-closed sink should return error on connection failure")
	}
}

func TestSinkNotDurable(t *testing.T) {
	sink, err := NewSink(Config{
		URL:           "https://hooks.example.test/loom",
		AllowUnsigned: true,
		Destination: DestinationPolicy{
			Resolver: staticResolver(net.ParseIP("1.1.1.1")),
		},
		HTTPClient: &http.Client{Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sink.Durable() {
		t.Fatal("webhook sink should not be durable")
	}
}

func TestNewSinkRequiresURL(t *testing.T) {
	_, err := NewSink(Config{Secret: "s"})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestVerifyEnvelopeRejectsTamperReplayAndWrongKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ev := audit.Event{ID: "evt-9", Operation: "op"}
	eventBody, _ := json.Marshal(ev)
	digest := "sha256:" + hex.EncodeToString(hashSHA256(eventBody))
	envelope := Envelope{Version: signatureVersion, EventID: "evt-9", Timestamp: now.Unix(), Digest: digest, Event: ev}
	body, _ := json.Marshal(envelope)
	secret := "rotate-me"
	sig := signPayload(secret, envelope.Timestamp, envelope.EventID, digest, body)
	headers := http.Header{}
	headers.Set("X-Loom-Signature", sig)
	headers.Set("X-Loom-Key-Id", "current")

	if _, err := VerifyEnvelope(body, headers, "", map[string]string{"current": secret}, now, time.Minute); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	// Tamper body
	tampered := append([]byte{}, body...)
	tampered[len(tampered)/2] ^= 0xff
	if _, err := VerifyEnvelope(tampered, headers, secret, nil, now, time.Minute); err == nil {
		t.Fatal("tampered body accepted")
	}
	// Wrong key
	if _, err := VerifyEnvelope(body, headers, "other", nil, now, time.Minute); err == nil {
		t.Fatal("wrong secret accepted")
	}
	// Expired
	if _, err := VerifyEnvelope(body, headers, secret, nil, now.Add(10*time.Minute), time.Minute); err == nil {
		t.Fatal("expired timestamp accepted")
	}
	// Rotation map
	if _, err := VerifyEnvelope(body, headers, "old", map[string]string{"current": secret}, now, time.Minute); err != nil {
		t.Fatalf("rotation secret rejected: %v", err)
	}
}

func TestRedirectsDisabledByDefault(t *testing.T) {
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redir.Close()

	// Custom client that still uses default redirect following would follow;
	// our sink forces CheckRedirect denial when HTTPClient is nil. With a
	// provided client we install a deny-redirect policy unless AllowRedirects.
	client := redir.Client()
	sink, err := NewSink(Config{
		URL:    redir.URL,
		Secret: "s",
		Destination: DestinationPolicy{
			AllowPrivate: true,
			Resolver:     staticResolver(net.ParseIP("127.0.0.1")),
		},
		HTTPClient: client,
		FailClosed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(context.Background(), audit.Event{ID: "e1"}); err == nil {
		t.Fatal("redirect following must fail closed by default")
	}
}

func TestDialRejectsRebindingToPrivateIP(t *testing.T) {
	// Resolver returns public IP at construction/delivery validation, but the
	// dial-time lookup flips to a private address — must refuse to connect.
	flip := &flipResolver{
		first:  []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}},
		second: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}},
	}
	transport := safeTransport(DestinationPolicy{Resolver: flip}, nil, time.Second)
	client := &http.Client{Timeout: time.Second, Transport: transport}
	sink, err := NewSink(Config{
		URL:        "https://rebinding.example/hook",
		Secret:     "s",
		FailClosed: true,
		Destination: DestinationPolicy{
			Resolver: flip,
		},
		HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force dial path through transport (not short-circuited by test server).
	if err := sink.Write(context.Background(), audit.Event{ID: "e1"}); err == nil {
		t.Fatal("DNS rebinding to loopback must fail")
	}
}

type staticResolver net.IP

func (s staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	ip := net.IP(s)
	if ip == nil {
		return nil, fmt.Errorf("nil ip")
	}
	return []net.IPAddr{{IP: ip}}, nil
}

type flipResolver struct {
	n      atomic.Int32
	first  []net.IPAddr
	second []net.IPAddr
}

func (f *flipResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	if f.n.Add(1) == 1 {
		return f.first, nil
	}
	return f.second, nil
}

// silence unused import guards for strconv in case refactor
var _ = strconv.Itoa
var _ = hmac.Equal
var _ = sha256.New
var _ = strings.Contains
