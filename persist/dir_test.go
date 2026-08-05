package persist_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loreste/loom/persist"
)

// TestEnsureDirTightensExistingDir: a pre-existing loose dir must be
// chmodded to 0700 (MkdirAll alone leaves it loose).
func TestEnsureDirTightensExistingDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := persist.EnsureDir(root); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("perm = %o, want 700", got)
	}
}
