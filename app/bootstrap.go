package app

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/loreste/loom/config"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
)

// SeedUser provisions a principal and optional op grants at bootstrap.
type SeedUser struct {
	ID    core.PrincipalID
	Token string
	Home  core.BoundaryID
	// Caps are capability strings held by the principal (e.g. "order.create").
	Caps []string
	// Ops are explicit policy/resource/field grants.
	Ops []SeedOp
	// DB optional governed SQL access (requires EnableDBOps + caps).
	DB *DBAccess
}

// SeedOp is one GrantOp during bootstrap.
type SeedOp struct {
	Op            string
	ResType       string
	ResID         string
	Fields        []string
}

// BootstrapConfig is a one-shot embed setup: open DB, migrate, register ops, seed users.
//
// Drivers must be imported by the main package (e.g. modernc.org/sqlite, pgx stdlib).
type BootstrapConfig struct {
	Config

	// DB application database. If nil and OpenDBFromEnv, loads LOOM_APP_DB_*.
	DB *config.AppDB
	// OpenDBFromEnv loads LOOM_APP_DB_* when DB is nil.
	OpenDBFromEnv bool
	// Migrations applied on raw *sql.DB before the pool is registered with Loom.
	// DDL stays outside the app SQL path by design.
	Migrations []db.Migration
	// EnableDBOps registers db.query / db.exec when true.
	EnableDBOps bool
	// Setup runs after the pool is registered (register domain ops here).
	// pool is the registered name (default "main"); empty if no DB was opened.
	Setup func(a *App, pool string) error
	// Users seeded after Setup.
	Users []SeedUser
}

// BootstrapResult carries the app and metadata about what was opened.
type BootstrapResult struct {
	App  *App
	Pool string
	// Dialect of the opened app DB (unknown if none).
	Dialect db.Dialect
}

// Bootstrap constructs an App, optionally opens/migrates an app DB, runs Setup, seeds users.
// On any error after App creation the App is closed before returning.
func Bootstrap(ctx context.Context, cfg BootstrapConfig) (*BootstrapResult, error) {
	a, err := New(cfg.Config)
	if err != nil {
		return nil, err
	}
	res := &BootstrapResult{App: a}
	ok := false
	defer func() {
		if !ok {
			_ = a.Close()
		}
	}()

	appDB, err := resolveAppDB(cfg)
	if err != nil {
		return nil, err
	}

	if appDB != nil {
		pool, dialect, err := openMigrateRegister(ctx, a, *appDB, cfg.Migrations)
		if err != nil {
			return nil, err
		}
		res.Pool = pool
		res.Dialect = dialect
	}

	if cfg.EnableDBOps {
		if err := a.EnableDBOps(); err != nil {
			return nil, fmt.Errorf("enable db ops: %w", err)
		}
	}

	if cfg.Setup != nil {
		if err := cfg.Setup(a, res.Pool); err != nil {
			return nil, fmt.Errorf("setup: %w", err)
		}
	}

	for i, u := range cfg.Users {
		if err := seedUser(a, u); err != nil {
			return nil, fmt.Errorf("seed user[%d] %s: %w", i, u.ID, err)
		}
	}

	ok = true
	return res, nil
}

func resolveAppDB(cfg BootstrapConfig) (*config.AppDB, error) {
	if cfg.DB != nil {
		if cfg.DB.URL == "" {
			return nil, nil
		}
		if err := cfg.DB.Validate(); err != nil {
			return nil, err
		}
		c := *cfg.DB
		if c.Pool == "" {
			c.Pool = "main"
		}
		return &c, nil
	}
	if !cfg.OpenDBFromEnv {
		return nil, nil
	}
	c := config.LoadAppDB()
	if c.URL == "" {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func openMigrateRegister(ctx context.Context, a *App, appDB config.AppDB, migrations []db.Migration) (string, db.Dialect, error) {
	pool := appDB.Pool
	if pool == "" {
		pool = "main"
	}
	dialect := db.DetectDialect(appDB.Driver)
	if dialect == db.DialectUnknown {
		return "", dialect, fmt.Errorf("%w: unknown dialect for driver %q", core.ErrInvalidArgument, appDB.Driver)
	}

	sqldb, err := sql.Open(appDB.Driver, appDB.URL)
	if err != nil {
		return "", dialect, fmt.Errorf("open db: %w", err)
	}
	// Ping early so bad DSNs fail before migration.
	pingCtx := ctx
	if ctx == nil {
		pingCtx = context.Background()
	}
	if err := sqldb.PingContext(pingCtx); err != nil {
		_ = sqldb.Close()
		return "", dialect, fmt.Errorf("ping db: %w", err)
	}

	if len(migrations) > 0 {
		mig := db.NewMigrator(sqldb, dialect)
		if err := mig.Apply(pingCtx, migrations); err != nil {
			_ = sqldb.Close()
			return "", dialect, fmt.Errorf("migrate: %w", err)
		}
	}

	opts := appDB.Options()
	if err := a.DBs.RegisterDB(pool, sqldb, opts); err != nil {
		_ = sqldb.Close()
		return "", dialect, err
	}
	// Registry owns the pool for Close().
	return pool, dialect, nil
}

func seedUser(a *App, u SeedUser) error {
	if u.ID == "" || u.Token == "" {
		return fmt.Errorf("%w: id and token required", core.ErrInvalidArgument)
	}
	if err := a.AddUser(u.ID, u.Token, u.Home, u.Caps); err != nil {
		return err
	}
	for _, op := range u.Ops {
		if op.Op == "" {
			return fmt.Errorf("%w: empty op in seed", core.ErrInvalidArgument)
		}
		if err := a.GrantOp(u.ID, u.Home, op.Op, op.ResType, op.ResID, op.Fields); err != nil {
			return err
		}
	}
	if u.DB != nil {
		g := *u.DB
		if g.Principal == "" {
			g.Principal = u.ID
		}
		if g.Boundary == "" {
			g.Boundary = u.Home
		}
		if err := a.GrantDBAccess(g); err != nil {
			return err
		}
	}
	return nil
}
