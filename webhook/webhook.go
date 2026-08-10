// Package webhook delivers audit events to HTTP endpoints.
//
// Delivery is best-effort and nondurable unless paired with a durable outbox.
// Production configurations must use HTTPS destinations, a signing secret, and
// must not enable AllowHTTP/AllowPrivate. Prefer FailClosed only when the
// webhook is part of a durable pipeline that can retry; a failed synchronous
// webhook after a business side effect must not rewrite that effect as
// unexecuted (use durable audit storage + outbox for that guarantee).
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
)

const (
	signatureVersion     = "v1"
	defaultTimeout       = 5 * time.Second
	defaultMaxRespBytes  = 64 << 10
	defaultReplayWindow  = 5 * time.Minute
	maxSecretBytes       = 1 << 12
)

// Config for a webhook delivery sink.
type Config struct {
	// URL is the endpoint that receives POST requests with JSON audit events.
	URL string
	// Secret signs the payload with HMAC-SHA256. Required unless
	// AllowUnsigned is set (development only).
	Secret string
	// KeyID identifies the signing secret for rotation. Optional.
	KeyID string
	// Secrets maps key IDs to HMAC secrets for receivers verifying rotation.
	// Delivery uses Secret/KeyID; Secrets is for Verify helpers.
	Secrets map[string]string
	// Timeout for each HTTP request. Default 5s.
	Timeout time.Duration
	// MaxResponseBytes bounds how much of the response body is drained.
	MaxResponseBytes int64
	// Filter returns true for events that should be delivered. Nil sends all.
	Filter func(audit.Event) bool
	// FailClosed propagates delivery errors to the audit pipeline. Default
	// false (best-effort). Do not use FailClosed as a substitute for a durable
	// outbox after side effects.
	FailClosed bool
	// AllowUnsigned permits delivery without a signing secret. Development only.
	AllowUnsigned bool
	// Destination policy. Production should leave AllowHTTP/AllowPrivate false
	// and set AllowHosts when the destination set is known.
	Destination DestinationPolicy
	// HTTPClient is injectable for tests. When nil, a safe client is built.
	// Providing a custom client bypasses dial-time rebinding defenses unless
	// the caller reimplements them.
	HTTPClient *http.Client
	// Now is injectable for signature timestamps.
	Now func() time.Time
}

// Sink delivers audit events to an HTTP endpoint.
type Sink struct {
	cfg    Config
	client *http.Client
	dest   *validatedURL
}

// NewSink constructs a webhook sink with destination validation.
func NewSink(cfg Config) (*Sink, error) {
	return NewSinkContext(context.Background(), cfg)
}

// NewSinkContext constructs a webhook sink, resolving the destination under ctx.
func NewSinkContext(ctx context.Context, cfg Config) (*Sink, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("%w: webhook URL required", core.ErrInvalidArgument)
	}
	if !cfg.AllowUnsigned && strings.TrimSpace(cfg.Secret) == "" {
		return nil, fmt.Errorf("%w: webhook signing secret is required (set AllowUnsigned only for development)", core.ErrInvalidArgument)
	}
	if len(cfg.Secret) > maxSecretBytes {
		return nil, fmt.Errorf("%w: webhook secret exceeds safe maximum", core.ErrInvalidArgument)
	}
	dest, err := validateDestination(ctx, cfg.URL, cfg.Destination)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxRespBytes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := cfg.HTTPClient
	if client == nil {
		transport := safeTransport(cfg.Destination, nil, timeout)
		client = &http.Client{
			Timeout:       timeout,
			Transport:     transport,
			CheckRedirect: checkRedirect(cfg.Destination),
		}
	} else if client.CheckRedirect == nil && !cfg.Destination.AllowRedirects {
		// Preserve caller transport but still refuse redirects by default.
		clone := *client
		clone.CheckRedirect = checkRedirect(cfg.Destination)
		client = &clone
	}
	return &Sink{cfg: cfg, client: client, dest: dest}, nil
}

// Durable returns false. Webhook delivery is best-effort and nondurable.
func (s *Sink) Durable() bool { return false }

// Write delivers an event. On error with FailClosed=false (default), logs
// and returns nil so the audit pipeline is not blocked.
func (s *Sink) Write(ctx context.Context, ev audit.Event) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("webhook: sink is not configured")
	}
	if s.cfg.Filter != nil && !s.cfg.Filter(ev) {
		return nil
	}
	if err := s.deliver(ctx, ev); err != nil {
		if s.cfg.FailClosed {
			return err
		}
		// Never log secrets, signatures, or unrestricted payloads.
		log.Printf("loom/webhook: delivery failed")
	}
	return nil
}

// Envelope is the signed wire format for webhook receivers.
type Envelope struct {
	Version   string      `json:"v"`
	EventID   string      `json:"id"`
	Timestamp int64       `json:"ts"`
	Digest    string      `json:"digest"`
	Event     audit.Event `json:"event"`
}

// DeliverEvent posts one audit event. Workers and the best-effort sink share
// this path so signing, destination checks, and response bounds stay identical.
func (s *Sink) DeliverEvent(ctx context.Context, ev audit.Event) error {
	return s.deliver(ctx, ev)
}

func (s *Sink) deliver(ctx context.Context, ev audit.Event) error {
	if s == nil || s.client == nil || s.dest == nil {
		return fmt.Errorf("webhook: sink is not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Re-resolve destination at delivery time against DNS rebinding after
	// NewSink, unless the caller supplied a custom HTTP client.
	if s.cfg.HTTPClient == nil {
		if _, err := validateDestination(ctx, s.cfg.URL, s.cfg.Destination); err != nil {
			return err
		}
	}
	eventID := strings.TrimSpace(ev.ID)
	if eventID == "" {
		eventID = newEventID()
	}
	eventBody, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	digest := "sha256:" + hex.EncodeToString(hashSHA256(eventBody))
	now := s.cfg.Now().UTC()
	envelope := Envelope{
		Version:   signatureVersion,
		EventID:   eventID,
		Timestamp: now.Unix(),
		Digest:    digest,
		Event:     ev,
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.dest.raw, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "loom-webhook/1.0")
	req.Header.Set("X-Loom-Event-Id", eventID)
	req.Header.Set("X-Loom-Timestamp", strconv.FormatInt(envelope.Timestamp, 10))
	req.Header.Set("X-Loom-Content-Digest", digest)
	req.Header.Set("X-Loom-Signature-Version", signatureVersion)
	if s.cfg.Secret != "" {
		if s.cfg.KeyID != "" {
			req.Header.Set("X-Loom-Key-Id", s.cfg.KeyID)
		}
		req.Header.Set("X-Loom-Signature", signPayload(s.cfg.Secret, envelope.Timestamp, eventID, digest, body))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a bounded prefix so connections can be reused without retaining
	// arbitrary remote content in memory.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s.cfg.MaxResponseBytes+1))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}
	return nil
}

func signPayload(secret string, ts int64, eventID, digest string, body []byte) string {
	// Signed material binds time, event id, content digest, and raw body.
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%s\n%d\n%s\n%s\n", signatureVersion, ts, eventID, digest)
	mac.Write(body)
	return signatureVersion + "=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyEnvelope checks a signed webhook body using constant-time compare.
// window is the allowed clock skew for the timestamp; zero uses 5 minutes.
func VerifyEnvelope(body []byte, headers http.Header, secret string, secrets map[string]string, now time.Time, window time.Duration) (Envelope, error) {
	var envelope Envelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("%w: invalid webhook envelope", core.ErrInvalidArgument)
	}
	if envelope.Version != signatureVersion {
		return Envelope{}, fmt.Errorf("%w: unsupported signature version", core.ErrInvalidArgument)
	}
	if window <= 0 {
		window = defaultReplayWindow
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ts := time.Unix(envelope.Timestamp, 0).UTC()
	if ts.After(now.Add(window)) || now.After(ts.Add(window)) {
		return Envelope{}, fmt.Errorf("%w: webhook timestamp outside replay window", core.ErrInvalidArgument)
	}
	keyID := headers.Get("X-Loom-Key-Id")
	useSecret := secret
	if keyID != "" && len(secrets) > 0 {
		if rotated, ok := secrets[keyID]; ok {
			useSecret = rotated
		} else if secret == "" {
			return Envelope{}, fmt.Errorf("%w: unknown webhook key id", core.ErrInvalidArgument)
		}
	}
	if useSecret == "" {
		return Envelope{}, fmt.Errorf("%w: webhook secret required for verification", core.ErrInvalidArgument)
	}
	want := signPayload(useSecret, envelope.Timestamp, envelope.EventID, envelope.Digest, body)
	got := headers.Get("X-Loom-Signature")
	if !hmac.Equal([]byte(got), []byte(want)) {
		return Envelope{}, fmt.Errorf("%w: webhook signature mismatch", core.ErrInvalidArgument)
	}
	// Recompute digest over the event object to detect envelope/event split tampering.
	eventBody, err := json.Marshal(envelope.Event)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: invalid event", core.ErrInvalidArgument)
	}
	expectDigest := "sha256:" + hex.EncodeToString(hashSHA256(eventBody))
	if !hmac.Equal([]byte(expectDigest), []byte(envelope.Digest)) {
		return Envelope{}, fmt.Errorf("%w: webhook content digest mismatch", core.ErrInvalidArgument)
	}
	return envelope, nil
}

func hashSHA256(body []byte) []byte {
	sum := sha256.Sum256(body)
	return sum[:]
}

func newEventID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("evt-%d", time.Now().UTC().UnixNano())
	}
	return "evt-" + hex.EncodeToString(raw[:])
}
