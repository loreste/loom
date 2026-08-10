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

// buildWebhookAuditSink returns the audit.Sink used on the emit path.
// durableOutbox may be nil; then only the best-effort sink is available.
func buildWebhookAuditSink(ctx context.Context, cfg WebhookConfig, durableOutbox webhook.Outbox) (audit.Sink, *webhook.Sink, error) {
	deliverer, err := buildHTTPDeliverer(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	if deliverer == nil {
		return nil, nil, nil
	}
	if cfg.Durable && durableOutbox != nil {
		outboxSink, err := webhook.NewOutboxSink(durableOutbox)
		if err != nil {
			return nil, nil, err
		}
		return outboxSink, deliverer, nil
	}
	// Explicit nondurable path for development.
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
