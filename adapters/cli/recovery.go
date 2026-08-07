package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/recovery"
)

type recoveryVerificationRequest struct {
	ExecutionID      string `json:"execution_id"`
	Operation        string `json:"operation"`
	OperationVersion string `json:"operation_version"`
}

type recoveryVerificationResponse struct {
	Confirmed bool         `json:"confirmed"`
	Outcome   core.Outcome `json:"outcome"`
	Note      string       `json:"note,omitempty"`
}

type remoteRecoveryVerifier struct {
	client *http.Client
	url    string
	token  string
}

func (v remoteRecoveryVerifier) Verify(ctx context.Context, record execution.Record) (recovery.Verification, error) {
	body, err := json.Marshal(recoveryVerificationRequest{
		ExecutionID: record.ExecutionID, Operation: record.Operation,
		OperationVersion: record.OperationVersion,
	})
	if err != nil {
		return recovery.Verification{}, fmt.Errorf("recovery verifier request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, bytes.NewReader(body))
	if err != nil {
		return recovery.Verification{}, fmt.Errorf("recovery verifier request")
	}
	req.Header.Set("Content-Type", "application/json")
	if v.token != "" {
		req.Header.Set("Authorization", "Bearer "+v.token)
	}
	res, err := v.client.Do(req)
	if err != nil {
		return recovery.Verification{}, fmt.Errorf("recovery verifier unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return recovery.Verification{}, fmt.Errorf("recovery verifier rejected request")
	}
	var response recoveryVerificationResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&response); err != nil {
		return recovery.Verification{}, fmt.Errorf("recovery verifier response invalid")
	}
	if response.Outcome != core.OutcomeAllowed && response.Outcome != core.OutcomeDenied {
		return recovery.Verification{}, fmt.Errorf("recovery verifier returned invalid outcome")
	}
	return recovery.Verification{Confirmed: response.Confirmed, Outcome: response.Outcome, Note: boundedRecoveryNote(response.Note)}, nil
}

type recoveryLoggerEscalator struct{ logger *log.Logger }

func (e recoveryLoggerEscalator) Escalate(_ context.Context, record execution.Record, _ error) error {
	e.logger.Printf("recovery operator review required execution_id=%s", record.ExecutionID)
	return nil
}

func (a *Adapter) runRecoveryWorker(ctx context.Context, args []string) int {
	if a == nil || a.Platform == nil || a.Platform.ExecutionStatus == nil || a.Platform.RecoveryQueue == nil {
		fmt.Fprintln(a.errW(), "recovery-worker requires a configured durable platform")
		return 2
	}
	flags := parseFlags(args)
	verifierURL := flags["verifier-url"]
	if verifierURL == "" {
		verifierURL = os.Getenv("LOOM_RECOVERY_VERIFIER_URL")
	}
	if err := validateRecoveryVerifierURL(verifierURL); err != nil {
		fmt.Fprintln(a.errW(), "recovery-worker:", err)
		return 2
	}
	token := flags["verifier-token"]
	if token == "" {
		token = os.Getenv("LOOM_RECOVERY_VERIFIER_TOKEN")
	}
	worker, err := recovery.NewWorker(recovery.Config{
		Queue: a.Platform.RecoveryQueue, Store: a.Platform.ExecutionStatus,
		Verifier:    remoteRecoveryVerifier{client: &http.Client{Timeout: 45 * time.Second}, url: verifierURL, token: token},
		Escalator:   recoveryLoggerEscalator{logger: log.New(a.errW(), "loom recovery: ", log.LstdFlags)},
		Owner:       recoveryValue(flags, "owner", "LOOM_RECOVERY_OWNER", "loom-recovery-worker"),
		Lease:       recoveryDuration(flags, "lease", "LOOM_RECOVERY_LEASE", 5*time.Minute),
		Poll:        recoveryDuration(flags, "poll", "LOOM_RECOVERY_POLL", 5*time.Second),
		BackoffBase: recoveryDuration(flags, "backoff-base", "LOOM_RECOVERY_BACKOFF_BASE", time.Second),
		BackoffMax:  recoveryDuration(flags, "backoff-max", "LOOM_RECOVERY_BACKOFF_MAX", 5*time.Minute),
		MaxAttempts: recoveryInt(flags, "max-attempts", "LOOM_RECOVERY_MAX_ATTEMPTS", 8),
		Logger:      log.New(a.errW(), "loom recovery: ", log.LstdFlags),
		Observer:    a.Platform.Metrics,
	})
	if err != nil {
		fmt.Fprintln(a.errW(), "recovery-worker:", err)
		return 2
	}
	workerCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := worker.Run(workerCtx); err != nil && workerCtx.Err() == nil {
		fmt.Fprintln(a.errW(), "recovery-worker:", err)
		return 1
	}
	return 0
}

func validateRecoveryVerifierURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("LOOM_RECOVERY_VERIFIER_URL must be an absolute URL")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return fmt.Errorf("recovery verifier must use HTTPS outside localhost")
	}
	return nil
}

func recoveryValue(flags map[string]string, flag, env, fallback string) string {
	if value := strings.TrimSpace(flags[flag]); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv(env)); value != "" {
		return value
	}
	return fallback
}

func recoveryDuration(flags map[string]string, flag, env string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(flags[flag])
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(env))
	}
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func recoveryInt(flags map[string]string, flag, env string, fallback int) int {
	raw := strings.TrimSpace(flags[flag])
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(env))
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func boundedRecoveryNote(note string) string {
	note = strings.TrimSpace(note)
	if len(note) > 512 {
		return note[:512]
	}
	return note
}
