package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

// AppDB is optional application database wiring from the environment.
// Used by embed apps / workers — not Loom's own metadata Postgres store.
type AppDB struct {
	// URL e.g. postgres://… or file:app.db / path for sqlite.
	URL string
	// Driver defaults: pgx for postgres URLs, sqlite for file:/.db URLs;
	// empty for unrecognized schemes (Validate then rejects the config).
	Driver string
	// Pool name defaults to "main".
	Pool string
	// Tables comma-separated allowlist.
	Tables []string
	// Boundaries comma-separated allowed boundaries.
	Boundaries []core.BoundaryID
	// ReadOnly pool.
	ReadOnly bool
	// MaxRows default 1000.
	MaxRows int
	// StatementTimeout.
	StatementTimeout time.Duration
}

// LoadAppDB reads LOOM_APP_DB_* variables. Empty URL means not configured.
func LoadAppDB() AppDB {
	url := os.Getenv("LOOM_APP_DB_URL")
	driver := os.Getenv("LOOM_APP_DB_DRIVER")
	if driver == "" && url != "" {
		driver = guessDriver(url)
	}
	pool := env("LOOM_APP_DB_POOL", "main")
	var tables []string
	if t := os.Getenv("LOOM_APP_DB_TABLES"); t != "" {
		for _, p := range strings.Split(t, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				tables = append(tables, p)
			}
		}
	}
	var bounds []core.BoundaryID
	if b := os.Getenv("LOOM_APP_DB_BOUNDARIES"); b != "" {
		for _, p := range strings.Split(b, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				bounds = append(bounds, core.BoundaryID(p))
			}
		}
	}
	return AppDB{
		URL:              url,
		Driver:           driver,
		Pool:             pool,
		Tables:           tables,
		Boundaries:       bounds,
		ReadOnly:         envBool("LOOM_APP_DB_READONLY", false),
		MaxRows:          envInt("LOOM_APP_DB_MAX_ROWS", 1000),
		StatementTimeout: ParseDurationEnv("LOOM_APP_DB_TIMEOUT", 5*time.Second),
	}
}

func guessDriver(url string) string {
	u := strings.ToLower(url)
	switch {
	case strings.HasPrefix(u, "postgres://"), strings.HasPrefix(u, "postgresql://"):
		return "pgx"
	case strings.HasPrefix(u, "file:"), strings.HasSuffix(u, ".db"), strings.Contains(u, "mode=memory"):
		return "sqlite"
	default:
		// Unknown scheme: no silent fallback to sqlite. Empty driver makes
		// Validate reject the config (fail closed).
		return ""
	}
}

// Options converts to db.Options.
func (a AppDB) Options() db.Options {
	d := db.DetectDialect(a.Driver)
	return db.Options{
		DriverName:        a.Driver,
		Dialect:           d,
		AllowedTables:     append([]string(nil), a.Tables...),
		AllowedBoundaries: append([]core.BoundaryID(nil), a.Boundaries...),
		ReadOnly:          a.ReadOnly,
		MaxRows:           a.MaxRows,
		StatementTimeout:  a.StatementTimeout,
	}
}

// Validate checks AppDB when URL is set.
func (a AppDB) Validate() error {
	if a.URL == "" {
		return nil
	}
	if a.Driver == "" {
		return fmt.Errorf("LOOM_APP_DB_DRIVER required when LOOM_APP_DB_URL is set")
	}
	if a.Pool == "" {
		return fmt.Errorf("LOOM_APP_DB_POOL empty")
	}
	return nil
}
