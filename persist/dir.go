// Package persist helpers for on-disk Loom state (single node).
package persist

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/loreste/loom/core"
)

// Layout under a data directory.
const (
	FileApprovals   = "approvals.json"
	FileIdempotency = "idempotency.json"
	FileExecution   = "executions.json"
	FileAuditJSONL  = "audit.jsonl"
	DirTLS          = "tls"
)

// EnsureDir creates a private data directory (0700).
func EnsureDir(root string) error {
	if root == "" {
		return fmt.Errorf("%w: data dir required", core.ErrInvalidArgument)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	// MkdirAll does not tighten a pre-existing loose directory.
	return os.Chmod(root, 0o700)
}

// Path joins root and name.
func Path(root, name string) string {
	return filepath.Join(root, name)
}
