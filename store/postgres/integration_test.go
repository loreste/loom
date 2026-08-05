package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/loreste/loom/audit"
	"github.com/loreste/loom/core"
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
