package bootstrap

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/webhook"
)

// WebhookConfig configures optional audit webhook delivery.
//
// When Durable is true and a PostgreSQL outbox is available, Write only enqueues
// and a background or CLI worker performs signed HTTPS delivery with retry and
// dead-letter handling. When Durable is false, the best-effort Sink delivers
// inline (development only; clearly nondurable).
type WebhookConfig struct {
	URL           string
	Secret        string
	KeyID         string
	AllowHosts    []string
	FailClosed    bool
	AllowHTTP     bool
	AllowPrivate  bool
	AllowUnsigned bool
	Timeout       time.Duration
	// Durable prefers outbox enqueue over inline delivery when an Outbox is
	// supplied to buildWebhookAuditSink. Production with PostgreSQL should set
	// this true (the default when LOOM_DATABASE_URL is configured).
	Durable bool
	// RunWorker starts an in-process delivery worker after platform bootstrap.
	// Prefer a separate loom webhook-worker deployment in multi-replica setups.
	RunWorker bool
	// Worker knobs (used when RunWorker is true or by CLI worker).
	Owner       string
	Lease       time.Duration
	Poll        time.Duration
	BackoffBase time.Duration
	BackoffMax  time.Duration
	MaxAttempts int
}

func (c WebhookConfig) enabled() bool {
	return strings.TrimSpace(c.URL) != ""
}

func buildHTTPDeliverer(ctx context.Context, cfg WebhookConfig) (*webhook.Sink, error) {
	if !cfg.enabled() {
		return nil, nil
	}
	secret := cfg.Secret
	allowUnsigned := cfg.AllowUnsigned
	if secret == "" && !allowUnsigned {
		return nil, fmt.Errorf("webhook: signing secret is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return webhook.NewSinkContext(ctx, webhook.Config{
		URL:           cfg.URL,
		Secret:        secret,
		KeyID:         cfg.KeyID,
		Timeout:       timeout,
		FailClosed:    cfg.FailClosed,
		AllowUnsigned: allowUnsigned,
		Destination: webhook.DestinationPolicy{
			AllowHTTP:    cfg.AllowHTTP,
			AllowPrivate: cfg.AllowPrivate,
			AllowHosts:   append([]string(nil), cfg.AllowHosts...),
		},
	})
}

// buildWebhookDeliverer constructs the HTTPS deliverer used by workers (and by
// the development inline sink). It never attaches to the audit MultiSink when
// durable outbox mode is active — that path is atomic on the Postgres audit TX.
func buildWebhookDeliverer(ctx context.Context, cfg WebhookConfig) (*webhook.Sink, error) {
	return buildHTTPDeliverer(ctx, cfg)
}

// buildWebhookAuditSink returns an optional extra audit.Sink for development
// inline delivery. When durable+outbox, it returns (nil, deliverer) so bootstrap
// can enable atomic enqueue on the Postgres AuditSink instead of MultiSink fan-out.
func buildWebhookAuditSink(ctx context.Context, cfg WebhookConfig, durableOutbox webhook.Outbox, requireDurable bool) (audit.Sink, *webhook.Sink, error) {
	deliverer, err := buildHTTPDeliverer(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	if deliverer == nil {
		return nil, nil, nil
	}
	if cfg.Durable {
		if durableOutbox == nil {
			return nil, nil, fmt.Errorf("webhook: durable delivery requires PostgreSQL outbox (set LOOM_DATABASE_URL)")
		}
		// Atomic path: no separate sink — AuditSink.EnableWebhookOutbox handles enqueue.
		return nil, deliverer, nil
	}
	if requireDurable {
		return nil, nil, fmt.Errorf("webhook: nondurable inline delivery is not permitted when RequireDurable is set")
	}
	// Explicit nondurable path for development only.
	return deliverer, deliverer, nil
}

func newWebhookWorker(cfg WebhookConfig, outbox webhook.Outbox, deliverer *webhook.Sink, observer webhook.WorkerObserver, logger *log.Logger) (*webhook.Worker, error) {
	if outbox == nil || deliverer == nil {
		return nil, fmt.Errorf("webhook: outbox and deliverer required for worker")
	}
	owner := cfg.Owner
	if owner == "" {
		owner = "loom-webhook-worker"
	}
	lease := cfg.Lease
	if lease <= 0 {
		lease = 30 * time.Second
	}
	poll := cfg.Poll
	if poll <= 0 {
		poll = 2 * time.Second
	}
	return webhook.NewWorker(webhook.WorkerConfig{
		Outbox:      outbox,
		Deliverer:   webhook.HTTPDeliverer{Sink: deliverer},
		Owner:       owner,
		Lease:       lease,
		Poll:        poll,
		BackoffBase: cfg.BackoffBase,
		BackoffMax:  cfg.BackoffMax,
		MaxAttempts: cfg.MaxAttempts,
		Logger:      logger,
		Observer:    observer,
	})
}
