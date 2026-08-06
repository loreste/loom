package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/execution"
	"github.com/loreste/loom/idempotency"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/store/postgres"
)

func dsn(t *testing.T) string {
	t.Helper()
	u := os.Getenv("LOOM_DATABASE_URL")
	if u == "" {
		t.Skip("LOOM_DATABASE_URL not set; skip postgres integration")
	}
	return u
}

func TestPostgresApprovalIdempotencyAudit(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	tok := "pg-int-token-" + time.Now().Format("150405.000")
	if err := b.Approvals.Issue(tok, "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}

	// loom_approvals must store only token_hash = SHA-256 hex, never the raw token.
	sum := sha256.Sum256([]byte(tok))
	wantHash := hex.EncodeToString(sum[:])
	var storedHash string
	if err := b.DB.QueryRowContext(ctx,
		`SELECT token_hash FROM loom_approvals WHERE token_hash = $1`, wantHash,
	).Scan(&storedHash); err != nil {
		t.Fatalf("approval row keyed by sha256(token) not found: %v", err)
	}
	if storedHash == tok || len(storedHash) != 64 {
		t.Fatalf("token_hash = %q, want 64-char sha256 hex", storedHash)
	}
	var rawRows int
	if err := b.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM loom_approvals WHERE token_hash = $1`, tok,
	).Scan(&rawRows); err != nil {
		t.Fatal(err)
	}
	if rawRows != 0 {
		t.Fatal("raw approval token found in loom_approvals")
	}

	op := &core.Operation{
		Name:     "payment.capture",
		Risk:     core.RiskHigh,
		Approval: core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Effects:  []core.Effect{core.EffectMoney},
	}
	id := core.Identity{ID: "user:bob"}
	dec := b.Approvals.Evaluate(ctx, id, op, core.RiskHigh, "dev", tok)
	if !dec.Approved {
		t.Fatalf("approve: %+v", dec)
	}
	// Evaluate does not consume; Consume burns the single-use token.
	if err := b.Approvals.Consume(ctx, id, op, "dev", tok); err != nil {
		t.Fatalf("consume: %v", err)
	}
	dec = b.Approvals.Evaluate(ctx, id, op, core.RiskHigh, "dev", tok)
	if dec.Approved {
		t.Fatal("must be single-use")
	}

	key := "pg-idem-" + tok
	fp := "fp-1"
	if err := b.Idempotency.Begin(ctx, key, fp, time.Hour); err != nil {
		t.Fatal(err)
	}
	resp := core.Response{Allowed: true, Decision: core.DecisionAllow, Output: map[string]any{"ok": true}}
	if err := b.Idempotency.Complete(ctx, key, &idempotency.Stored{
		Fingerprint: fp,
		Response:    resp,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	st, ok, err := b.Idempotency.Get(ctx, key)
	if err != nil || !ok || !st.Response.Allowed {
		t.Fatalf("get: err=%v ok=%v st=%+v", err, ok, st)
	}
	// Re-Complete of an already-completed record must fail and must not
	// retroactively change the replayed response.
	tampered := core.Response{Allowed: true, Decision: core.DecisionAllow, Output: map[string]any{"ok": false, "tampered": true}}
	if err := b.Idempotency.Complete(ctx, key, &idempotency.Stored{
		Fingerprint: fp,
		Response:    tampered,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err == nil {
		t.Fatal("re-Complete of completed record must fail")
	}
	st2, ok, err := b.Idempotency.Get(ctx, key)
	if err != nil || !ok {
		t.Fatalf("get after re-complete: err=%v ok=%v", err, ok)
	}
	if _, tamperedFound := st2.Response.Output["tampered"]; tamperedFound {
		t.Fatal("re-Complete retroactively changed the replayed response")
	}
	if err := b.Idempotency.Begin(ctx, key, "fp-other", time.Hour); err == nil {
		t.Fatal("conflict expected")
	}

	if err := b.Audit.Write(ctx, audit.Event{
		ID:        "audit-" + tok,
		Timestamp: time.Now().UTC(),
		TraceID:   "tr-1",
		Decision:  "allow",
		Operation: "payment.capture",
		Principal: "user:bob",
		Input:     map[string]any{"amount": 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := postgres.Ready(ctx, b.DB); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresConcurrentConsume(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	tok := "pg-race-" + time.Now().Format("150405.000000")
	_ = b.Approvals.Issue(tok, "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour)
	op := &core.Operation{
		Name:     "payment.capture",
		Approval: core.ApprovalPolicy{MinRisk: core.RiskHigh},
	}
	id := core.Identity{ID: "user:bob"}

	type res struct{ ok bool }
	ch := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			d := b.Approvals.Evaluate(ctx, id, op, core.RiskHigh, "dev", tok)
			if !d.Approved {
				ch <- res{ok: false}
				return
			}
			// The burn is the atomic step: exactly one Consume must win.
			ch <- res{ok: b.Approvals.Consume(ctx, id, op, "dev", tok) == nil}
		}()
	}
	a, bres := <-ch, <-ch
	// Exactly one consumer must succeed (serializable consume); both succeeding
	// is a double spend, both failing means the single-use token never worked.
	if a.ok == bres.ok {
		t.Fatalf("exactly one consumer must succeed, got a=%v b=%v", a.ok, bres.ok)
	}
}

func TestPostgresExecutionReconcileAndRecoveryLease(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	id := "pg-execution-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	record := execution.Record{
		ExecutionID:      id,
		Operation:        "payment.capture",
		OperationVersion: "1",
		Outcome:          core.OutcomeExecutedUnconfirmed,
		State:            execution.StateExecutedUnconfirmed,
		Response:         core.Response{Outcome: core.OutcomeExecutedUnconfirmed, ExecutionID: id},
	}
	if err := b.ExecutionStatus.Put(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := b.ExecutionStatus.Put(ctx, record); !errors.Is(err, core.ErrAlreadyExists) {
		t.Fatalf("duplicate execution Put error = %v, want ErrAlreadyExists", err)
	}
	if err := b.ExecutionStatus.Enqueue(ctx, idempotency.RecoveryRecord{
		ExecutionID: id,
		Key:         "pg-recovery-key-" + id,
		Fingerprint: "pg-recovery-fingerprint",
		Response:    record.Response,
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExecutionStatus.MarkRecoveryQueued(ctx, id); err != nil {
		t.Fatal(err)
	}

	lease, ok, err := b.ExecutionStatus.ClaimRecovery(ctx, "worker-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("claim recovery: err=%v ok=%v", err, ok)
	}
	if lease.Record.ExecutionID != id || lease.Owner != "worker-a" || lease.LeaseID == "" {
		t.Fatalf("unexpected lease: %+v", lease)
	}
	owner, _, found, err := b.ExecutionStatus.RecoveryOwner(ctx, id)
	if err != nil || !found || owner != "worker-a" {
		t.Fatalf("owner lookup: owner=%q found=%v err=%v", owner, found, err)
	}
	if _, ok, err := b.ExecutionStatus.ClaimRecovery(ctx, "worker-b", time.Minute); err != nil || ok {
		t.Fatalf("live lease must exclude another worker: err=%v ok=%v", err, ok)
	}
	if err := b.ExecutionStatus.ReleaseRecovery(ctx, id, lease.LeaseID, false); err != nil {
		t.Fatal(err)
	}

	lease, ok, err = b.ExecutionStatus.ClaimRecovery(ctx, "worker-b", time.Minute)
	if err != nil || !ok {
		t.Fatalf("reclaim recovery: err=%v ok=%v", err, ok)
	}
	if err := b.ExecutionStatus.ReleaseRecovery(ctx, id, lease.LeaseID, true); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := b.ExecutionStatus.ClaimRecovery(ctx, "worker-c", time.Minute); err != nil || ok {
		t.Fatalf("completed recovery must leave queue: err=%v ok=%v", err, ok)
	}

	reconciled, err := b.ExecutionStatus.Reconcile(ctx, id, core.OutcomeAllowed, "confirmed")
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.State != execution.StateReconciled || !reconciled.Response.Allowed {
		t.Fatalf("unexpected reconciled execution: %+v", reconciled)
	}
	reloaded, found, err := b.ExecutionStatus.Get(ctx, id)
	if err != nil || !found || reloaded.State != execution.StateReconciled {
		t.Fatalf("reloaded execution: err=%v found=%v record=%+v", err, found, reloaded)
	}
	if _, err := b.ExecutionStatus.Reconcile(ctx, id, core.OutcomeDenied, "contradiction"); err == nil {
		t.Fatal("contradictory reconciliation must be rejected")
	}
	concurrentID := id + "-concurrent"
	concurrentRecord := record
	concurrentRecord.ExecutionID = concurrentID
	concurrentRecord.Response.ExecutionID = concurrentID
	if err := b.ExecutionStatus.Put(ctx, concurrentRecord); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.ExecutionStatus.Reconcile(ctx, concurrentID, core.OutcomeAllowed, "confirmed")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent same-outcome reconciliation: %v", err)
		}
	}
	if _, err := b.DB.ExecContext(ctx, `UPDATE loom_executions SET updated_at = NOW() - INTERVAL '1 day' WHERE execution_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	archived, err := b.ExecutionStatus.Archive(ctx, time.Now().Add(-time.Hour), 10)
	if err != nil || archived != 1 {
		t.Fatalf("archive: count=%d err=%v", archived, err)
	}
	var archiveCount int
	if err := b.DB.QueryRowContext(ctx, `SELECT count(*) FROM loom_execution_archive WHERE execution_id = $1`, id).Scan(&archiveCount); err != nil {
		t.Fatal(err)
	}
	if archiveCount != 1 {
		t.Fatalf("archived execution count = %d, want 1", archiveCount)
	}
}

// TestPostgresMigrateRefusesDowngrade: a database stamped with a newer schema
// version must refuse migration; a corrupt version string must error too
// (never silently treated as 0).
func TestPostgresMigrateRefusesDowngrade(t *testing.T) {
	ctx := context.Background()
	db, err := postgres.Open(dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	cur, err := postgres.CurrentVersion(ctx, db)
	if err != nil || cur != postgres.SchemaVersion {
		t.Fatalf("version = %d err=%v, want %d", cur, err, postgres.SchemaVersion)
	}

	// Stomp the version forward; Migrate must refuse. Restore afterwards so
	// other tests sharing this database can still migrate.
	if _, err := db.ExecContext(ctx,
		`UPDATE loom_schema_meta SET value = '999' WHERE key = 'version'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`UPDATE loom_schema_meta SET value = $1 WHERE key = 'version'`, strconv.Itoa(postgres.SchemaVersion))
	})
	if err := postgres.Migrate(ctx, db); err == nil || !strings.Contains(err.Error(), "refusing downgrade") {
		t.Fatalf("downgrade not refused: %v", err)
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE loom_schema_meta SET value = 'not-a-number' WHERE key = 'version'`); err != nil {
		t.Fatal(err)
	}
	if err := postgres.Migrate(ctx, db); err == nil || !strings.Contains(err.Error(), "corrupt schema version") {
		t.Fatalf("corrupt version must error: %v", err)
	}
}

// TestPostgresPolicyStalePublish: non-increasing versions must be rejected,
// including the storage-layer guard for first-time concurrent publishes.
func TestPostgresPolicyStalePublish(t *testing.T) {
	ctx := context.Background()
	b, err := postgres.NewBundle(ctx, dsn(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })

	src := b.Policy
	src.ID = "stale-test-" + time.Now().Format("150405.000000")
	doc := &policy.Document{Version: 2, ID: src.ID, Rules: nil}
	if err := src.Publish(ctx, doc); err != nil {
		t.Fatal(err)
	}
	stale := &policy.Document{Version: 1, ID: src.ID}
	if err := src.Publish(ctx, stale); err == nil {
		t.Fatal("stale version publish must be rejected")
	}
	same := &policy.Document{Version: 2, ID: src.ID}
	if err := src.Publish(ctx, same); err == nil {
		t.Fatal("same version publish must be rejected")
	}
	loaded, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != 2 {
		t.Fatalf("version = %d, want 2 (stale publish must not win)", loaded.Version)
	}
}
func TestPostgresConcurrentMigrations(t *testing.T) {
	ctx := context.Background()
	databaseURL := dsn(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			db, err := postgres.Open(databaseURL)
			if err != nil {
				results <- err
				return
			}
			defer db.Close()
			results <- postgres.Migrate(ctx, db)
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent migration failed: %v", err)
		}
	}
}
