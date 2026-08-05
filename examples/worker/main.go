// Command worker: long-lived job processor through Loom (no HTTP).
//
//	go run ./examples/worker/
//
// Env (optional):
//
//	LOOM_APP_DB_URL=file:worker.db
//	LOOM_APP_DB_DRIVER=sqlite
//	LOOM_APP_DB_TABLES=orders
//	LOOM_APP_DB_BOUNDARIES=dev
//
// Stop with Ctrl+C.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/config"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/domains/orders"
	"github.com/loreste/loom/job"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(app.Config{})
	if err != nil {
		return err
	}
	defer a.Close()

	// DB: env or default local sqlite file
	appDB := config.LoadAppDB()
	var sqldb *sql.DB
	if appDB.URL != "" {
		if err := appDB.Validate(); err != nil {
			return err
		}
		sqldb, err = sql.Open(appDB.Driver, appDB.URL)
		if err != nil {
			return err
		}
	} else {
		sqldb, err = sql.Open("sqlite", "file:worker.db?cache=shared")
		if err != nil {
			return err
		}
		appDB = config.AppDB{
			Driver: "sqlite", Pool: "main",
			Tables: []string{"orders"}, Boundaries: []core.BoundaryID{"dev"},
		}
	}
	defer sqldb.Close()

	mig := db.NewMigrator(sqldb, db.DetectDialect(appDB.Driver))
	if err := mig.Apply(ctx, orders.Migrations()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	ver, _ := mig.CurrentVersion(ctx)
	fmt.Fprintf(os.Stderr, "schema v%d dialect=%s\n", ver, db.DetectDialect(appDB.Driver))

	opts := appDB.Options()
	if len(opts.AllowedTables) == 0 {
		opts.AllowedTables = []string{"orders"}
	}
	if len(opts.AllowedBoundaries) == 0 {
		opts.AllowedBoundaries = []core.BoundaryID{"dev"}
	}
	pool := appDB.Pool
	if pool == "" {
		pool = "main"
	}
	if err := a.DBs.RegisterDB(pool, sqldb, opts); err != nil {
		return err
	}
	if err := orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: pool}); err != nil {
		return err
	}

	token := "worker-token"
	if err := a.AddUser("svc:worker", token, "dev", []string{"order.create", "order.read"}); err != nil {
		return err
	}
	_ = a.GrantOp("svc:worker", "dev", "order.create", "order", "*",
		[]string{"id", "customer", "sku", "qty", "status", "created_at"})
	_ = a.GrantOp("svc:worker", "dev", "order.list", "order", "*", []string{"orders", "count"})

	// Durable SQL queue on the same app DB (approval tokens never stored).
	// Falls back to memory if queue init fails (should not for sqlite).
	var queue job.Queue
	sqlQ, err := job.NewSQLQueue(ctx, sqldb, job.SQLQueueOptions{
		Dialect: db.DetectDialect(appDB.Driver),
	})
	if err != nil {
		return fmt.Errorf("job queue: %w", err)
	}
	queue = sqlQ
	fmt.Fprintln(os.Stderr, "queue=sql (loom_jobs)")

	runID := time.Now().UnixNano()
	for i, payload := range []map[string]any{
		{"customer": "acme", "sku": "W-1", "qty": 1},
		{"customer": "globex", "sku": "W-2", "qty": 4},
		{"customer": "acme", "sku": "W-3", "qty": 2},
	} {
		id := fmt.Sprintf("job-%d-%d", runID, i+1)
		if err := queue.Enqueue(ctx, job.Job{
			ID:             id,
			Operation:      "order.create",
			Boundary:       "dev",
			Resource:       &core.ResourceRef{Type: "order", ID: "*"},
			Input:          payload,
			IdempotencyKey: id,
		}); err != nil {
			return fmt.Errorf("enqueue: %w", err)
		}
	}

	runner := &job.Runner{
		Queue:        queue,
		Caller:       a,
		Token:        token,
		PollInterval: 100 * time.Millisecond,
		OnResult: func(r job.Result) {
			if !r.Response.Allowed {
				fmt.Fprintf(os.Stderr, "job %s DENY %v\n", r.JobID, r.Response.Denial)
				return
			}
			fmt.Fprintf(os.Stderr, "job %s ok id=%v (%s)\n", r.JobID, r.Response.Output["id"], r.Duration)
		},
	}

	fmt.Fprintln(os.Stderr, "worker running via job.Runner (Ctrl+C to stop)…")
	errCh := make(chan error, 1)
	go func() { errCh <- runner.Run(ctx) }()

	// When queue drains, wait a beat then list and exit on idle (demo convenience).
	go func() {
		for {
			n, err := sqlQ.PendingCount(ctx)
			if err != nil || n == 0 {
				time.Sleep(300 * time.Millisecond)
				stop()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()

	<-ctx.Done()
	list := a.Call(context.Background(), core.Request{
		Operation:   "order.list",
		Credentials: core.Credentials{Token: token},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "order", ID: "*"},
		Input:       map[string]any{},
	})
	b, _ := json.MarshalIndent(list.Output, "", "  ")
	fmt.Println(string(b))
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			return err
		}
	default:
	}
	return nil
}
