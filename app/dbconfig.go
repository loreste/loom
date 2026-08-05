package app

import (
	"fmt"

	"github.com/loreste/loom/config"
	"github.com/loreste/loom/core"
)

// OpenDBFromEnv opens LOOM_APP_DB_* if configured.
// No-op (nil error) when LOOM_APP_DB_URL is empty.
//
// Drivers must be imported by the main package, e.g.:
//
//	_ "github.com/jackc/pgx/v5/stdlib"
//	_ "modernc.org/sqlite"
func (a *App) OpenDBFromEnv() error {
	if a == nil {
		return fmt.Errorf("%w: nil app", core.ErrInvalidArgument)
	}
	cfg := config.LoadAppDB()
	if cfg.URL == "" {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	return a.OpenDB(cfg.Pool, cfg.Driver, cfg.URL, cfg.Options())
}

// OpenDBFromConfig opens a pool from an AppDB struct.
func (a *App) OpenDBFromConfig(cfg config.AppDB) error {
	if a == nil {
		return fmt.Errorf("%w: nil app", core.ErrInvalidArgument)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.URL == "" {
		return fmt.Errorf("%w: empty database url", core.ErrInvalidArgument)
	}
	if cfg.Driver == "" {
		return fmt.Errorf("%w: empty driver", core.ErrInvalidArgument)
	}
	pool := cfg.Pool
	if pool == "" {
		pool = "main"
	}
	return a.OpenDB(pool, cfg.Driver, cfg.URL, cfg.Options())
}
