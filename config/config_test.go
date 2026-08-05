package config_test

import (
	"os"
	"testing"

	"github.com/loreste/loom/config"
)

func TestRequireDurable(t *testing.T) {
	t.Setenv("LOOM_REQUIRE_DURABLE", "true")
	t.Setenv("LOOM_DATA_DIR", "")
	t.Setenv("LOOM_DATABASE_URL", "")
	// clear may not unset if not set — ensure
	_ = os.Unsetenv("LOOM_DATA_DIR")
	_ = os.Unsetenv("LOOM_DATABASE_URL")
	c := config.Load()
	if err := c.Validate(); err == nil {
		t.Fatal("expected require durable failure")
	}
	t.Setenv("LOOM_DATA_DIR", "/tmp/loom")
	t.Setenv("LOOM_REDIS_URL", "redis://127.0.0.1:6379/0")
	t.Setenv("LOOM_JWT_SECRET", "configured-test-secret-1234")
	c = config.Load()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestJWTSecretTooShort(t *testing.T) {
	t.Setenv("LOOM_JWT_SECRET", "short")
	c := config.Load()
	if err := c.Validate(); err == nil {
		t.Fatal("short secret")
	}
}

// TestAppDBUnknownSchemeRejected: an unrecognized LOOM_APP_DB_URL scheme must
// not silently fall back to sqlite — LoadAppDB leaves Driver empty and
// Validate rejects it (fail closed).
func TestAppDBUnknownSchemeRejected(t *testing.T) {
	t.Setenv("LOOM_APP_DB_URL", "mysql://u:p@127.0.0.1:3306/app")
	t.Setenv("LOOM_APP_DB_DRIVER", "")
	a := config.LoadAppDB()
	if a.Driver != "" {
		t.Fatalf("driver = %q, want empty for unknown scheme", a.Driver)
	}
	if err := a.Validate(); err == nil {
		t.Fatal("Validate must reject unknown-scheme URL without explicit driver")
	}
}

func TestAppDBDriverGuesses(t *testing.T) {
	for url, want := range map[string]string{
		"postgres://u:p@h/db":                    "pgx",
		"postgresql://u:p@h/db":                  "pgx",
		"file:app.db":                            "sqlite",
		"/var/lib/app/app.db":                    "sqlite",
		"file::memory:?cache=shared&mode=memory": "sqlite",
	} {
		t.Setenv("LOOM_APP_DB_URL", url)
		t.Setenv("LOOM_APP_DB_DRIVER", "")
		if got := config.LoadAppDB().Driver; got != want {
			t.Errorf("url %q: driver = %q, want %q", url, got, want)
		}
	}
}
