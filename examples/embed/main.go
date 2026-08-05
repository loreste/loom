// Command embed demonstrates building with Loom without any HTTP API.
//
//	go run ./examples/embed/
//
// Flow: Bootstrap → migrate → open DB → least-privilege grants → db.exec/db.query
// through the full security pipeline (authn, policy, SQL guardrails, audit).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/config"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// One-shot embed setup: no server, no REST.
	res, err := app.Bootstrap(ctx, app.BootstrapConfig{
		DB: &config.AppDB{
			URL:        "file:embeddemo?mode=memory&cache=shared",
			Driver:     "sqlite",
			Pool:       "appdb",
			Tables:     []string{"notes"},
			Boundaries: []core.BoundaryID{"dev"},
			MaxRows:    50,
		},
		Migrations: []db.Migration{{
			Version: 1,
			Name:    "notes",
			Up: `CREATE TABLE IF NOT EXISTS notes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				body TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
		}},
		EnableDBOps: true,
		Users: []app.SeedUser{{
			ID: "user:dev", Token: "dev-token", Home: "dev",
			Caps: []string{"db.query", "db.exec"},
			DB: &app.DBAccess{
				Pool: "appdb", Query: true, Exec: true,
			},
		}},
	})
	if err != nil {
		return err
	}
	defer res.App.Close()
	a := res.App

	// Writes are high-risk → approval required.
	if err := a.IssueApproval("note-appr", "user:dev", "db.exec", "dev", core.RiskCritical, time.Hour); err != nil {
		return err
	}

	// All data access goes through Loom.Call (same pipeline as HTTP would use).
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

	// Blocked: table outside allowlist
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
