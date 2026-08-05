package policy

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/loreste/loom/core"
)

// Document is a versioned policy snapshot for multi-node sync.
// Higher Version always wins. Corrupt documents must not wipe live rules.
type Document struct {
	// Version is monotonically increasing. 0 means unset/invalid for publish.
	Version int64 `json:"version"`
	// ID identifies the policy namespace (default "default").
	ID string `json:"id,omitempty"`
	// Rules is the full rule set (replace semantics, not merge).
	Rules []Rule `json:"rules"`
	// UpdatedAt is advisory metadata.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Etags/hash optional for caches.
	Hash string `json:"hash,omitempty"`
}

// ParseDocument unmarshals JSON. Fail-closed on empty version when requireVersion.
func ParseDocument(raw []byte) (*Document, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty policy document", core.ErrInvalidArgument)
	}
	var d Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("policy: invalid json: %w", err)
	}
	if d.ID == "" {
		d.ID = "default"
	}
	// Validate each rule without applying
	for i, r := range d.Rules {
		if _, err := normalizeRule(r); err != nil {
			return nil, fmt.Errorf("policy: rule[%d]: %w", i, err)
		}
	}
	return &d, nil
}

// Bytes marshals the document.
func (d *Document) Bytes() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: nil document", core.ErrInvalidArgument)
	}
	return json.MarshalIndent(d, "", "  ")
}
