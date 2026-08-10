package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/loreste/loom/webhook"
)

func (a *Adapter) runWebhookWorker(ctx context.Context, args []string) int {
	if a == nil || a.Platform == nil || a.Platform.WebhookOutbox == nil || a.Platform.WebhookDeliverer == nil {
		fmt.Fprintln(a.errW(), "webhook-worker requires a platform with durable webhook outbox (LOOM_DATABASE_URL + LOOM_WEBHOOK_URL + LOOM_WEBHOOK_DURABLE)")
		return 2
	}
	flags := parseFlags(args)
	owner := recoveryValue(flags, "owner", "LOOM_WEBHOOK_OWNER", "loom-webhook-worker")
	worker, err := webhook.NewWorker(webhook.WorkerConfig{
		Outbox:      a.Platform.WebhookOutbox,
		Deliverer:   webhook.HTTPDeliverer{Sink: a.Platform.WebhookDeliverer},
		Owner:       owner,
		Lease:       recoveryDuration(flags, "lease", "LOOM_WEBHOOK_LEASE", 30*time.Second),
		Poll:        recoveryDuration(flags, "poll", "LOOM_WEBHOOK_POLL", 2*time.Second),
		BackoffBase: recoveryDuration(flags, "backoff-base", "LOOM_WEBHOOK_BACKOFF_BASE", time.Second),
		BackoffMax:  recoveryDuration(flags, "backoff-max", "LOOM_WEBHOOK_BACKOFF_MAX", 5*time.Minute),
		MaxAttempts: recoveryInt(flags, "max-attempts", "LOOM_WEBHOOK_MAX_ATTEMPTS", 8),
		Logger:      log.New(a.errW(), "loom webhook: ", log.LstdFlags),
		Observer:    a.Platform.Metrics,
	})
	if err != nil {
		fmt.Fprintln(a.errW(), "webhook-worker:", err)
		return 2
	}
	workerCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(a.errW(), "loom webhook-worker: draining durable outbox")
	if err := worker.Run(workerCtx); err != nil && err != context.Canceled {
		fmt.Fprintln(a.errW(), "webhook-worker:", err)
		return 1
	}
	return 0
}
