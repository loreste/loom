// Command embed demonstrates building with Loom without any HTTP API.
//
//	go run ./examples/embed/
//
// Flow: register user → open sqlite → enable db ops → call db.exec/db.query
// through the full security pipeline (authn, policy, SQL guardrails, audit).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/resource"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// 1) Embed Loom — no server, no REST.
	a, err := app.New(app.Config{})
	if err != nil {
		return err
	}
	defer a.Close()

	// 2) Connect database (DSN never exposed back out of the registry).
	sqldb, err := sql.Open("sqlite", "file:embeddemo?mode=memory&cache=shared")
	if err != nil {
		return err
	}
	defer sqldb.Close()
	if _, err := sqldb.Exec(`
		CREATE TABLE notes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			body TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`); err != nil {
		return err
	}
	if err := a.DBs.RegisterDB("appdb", sqldb, db.Options{
		AllowedTables:     []string{"notes"},
		AllowedBoundaries: []core.BoundaryID{"dev"},
		MaxRows:           50,
		StatementTimeout:  3 * time.Second,
	}); err != nil {
		return err
	}
	if err := a.EnableDBOps(); err != nil {
		return err
	}

	// 3) Identity + least privilege grants (default is DENY).
	if err := a.AddUser("user:dev", "dev-token", "dev", []string{"db.query", "db.exec"}); err != nil {
		return err
	}
	_ = a.AllowPolicy(policy.Rule{Principal: "user:dev", Boundary: "dev", Operation: "db.query", Priority: 10})
	_ = a.AllowPolicy(policy.Rule{Principal: "user:dev", Boundary: "dev", Operation: "db.exec", Priority: 10})
	_ = a.AllowResource(resource.Rule{
		Principal: "user:dev", Boundary: "dev", Type: "db", ID: "appdb",
		Operations: []string{"db.query", "db.exec"},
	})
	_ = a.AllowFields("user:dev", "dev", "db.query", []string{"pool", "columns", "rows", "count", "truncated"})
	_ = a.AllowFields("user:dev", "dev", "db.exec", []string{"pool", "rows_affected", "status"})

	// Writes are high-risk → approval required.
	if err := a.IssueApproval("note-appr", "user:dev", "db.exec", "dev", core.RiskCritical, time.Hour); err != nil {
		return err
	}

	// 4) All data access goes through Loom.Call (same pipeline as HTTP would use).
	write := a.Call(ctx, core.Request{
		Operation:   "db.exec",
		Credentials: core.Credentials{Token: "dev-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "appdb"},
		Input: map[string]any{
			"pool": "appdb",
			"sql":  "INSERT INTO notes (body, created_at) VALUES (?, ?)",
			"args": []any{"hello from embedded Loom", time.Now().UTC().Format(time.RFC3339)},
		},
		IdempotencyKey: "note-1",
		ApprovalToken:  "note-appr",
	})
	printJSON("db.exec", write)
	if !write.Allowed {
		return fmt.Errorf("write denied: %v", write.Denial)
	}

	read := a.Call(ctx, core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "dev-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "appdb"},
		Input: map[string]any{
			"pool": "appdb",
			"sql":  "SELECT id, body, created_at FROM notes ORDER BY id",
		},
	})
	printJSON("db.query", read)
	if !read.Allowed {
		return fmt.Errorf("read denied: %v", read.Denial)
	}

	// 5) Blocked: table outside allowlist
	blocked := a.Call(ctx, core.Request{
		Operation:   "db.query",
		Credentials: core.Credentials{Token: "dev-token"},
		Boundary:    "dev",
		Resource:    &core.ResourceRef{Type: "db", ID: "appdb"},
		Input: map[string]any{
			"pool": "appdb",
			"sql":  "SELECT * FROM sqlite_master",
		},
	})
	printJSON("blocked query", blocked)
	return nil
}

func printJSON(label string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Printf("== %s ==\n%s\n", label, b)
}
