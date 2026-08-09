// Package webhook delivers audit events to HTTP endpoints.
//
// By default, delivery is best-effort (fail-open): errors are logged but never
// propagated to the audit pipeline. Set Config.FailClosed for compliance
// webhooks where delivery failure must block the operation.
//
// The sink is not durable. Pair it with a durable sink via audit.MultiSink
// for production deployments.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/loreste/loom/audit"
)

// Config for a webhook delivery sink.
type Config struct {
	// URL is the endpoint that receives POST requests with JSON audit events.
	URL string
	// Secret signs the payload with HMAC-SHA256 (X-Loom-Signature header).
	// Empty disables signing.
	Secret string
	// Timeout for each HTTP request. Default 5s.
	Timeout time.Duration
	// Filter returns true for events that should be delivered. Nil sends all.
	Filter func(audit.Event) bool
	// FailClosed propagates delivery errors to the audit pipeline. Default
	// false (best-effort). Set true for compliance-critical webhooks.
	FailClosed bool
}

// Sink delivers audit events to an HTTP endpoint.
type Sink struct {
	cfg    Config
	client *http.Client
}

// NewSink constructs a webhook sink. URL is required.
func NewSink(cfg Config) (*Sink, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook: URL required")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &Sink{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
	}, nil
}

// Durable returns false. Webhook delivery is best-effort.
func (s *Sink) Durable() bool { return false }

// Write delivers an event. On error with FailClosed=false (default), logs
// and returns nil so the audit pipeline is not blocked.
func (s *Sink) Write(ctx context.Context, ev audit.Event) error {
	if s.cfg.Filter != nil && !s.cfg.Filter(ev) {
		return nil
	}
	if err := s.deliver(ctx, ev); err != nil {
		if s.cfg.FailClosed {
			return err
		}
		log.Printf("loom/webhook: %v", err)
	}
	return nil
}

func (s *Sink) deliver(ctx context.Context, ev audit.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "loom-webhook/1.0")
	if s.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
		mac.Write(body)
		req.Header.Set("X-Loom-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}
	return nil
}
