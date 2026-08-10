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

// ParseDocument unmarshals JSON with the same strict rules as file policies.
// Fail-closed on empty input, unknown fields, duplicate keys, and invalid rules.
// Callers must not replace live policy when this returns an error.
//
// Extra top-level keys such as "tests" (used by `loom policy test` fixtures)
// are accepted only when present as a raw array; they are ignored for rule
// loading so test fixtures remain single-file without weakening rule checks.
func ParseDocument(raw []byte) (*Document, error) {
	return ParseDocumentWithLimits(raw, Limits{})
}

// ParseDocumentWithLimits is ParseDocument with explicit resource bounds.
func ParseDocumentWithLimits(raw []byte, limits Limits) (*Document, error) {
	limits = limits.withDefaults()
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty policy document", core.ErrInvalidArgument)
	}
	if len(raw) > limits.MaxBytes {
		return nil, fmt.Errorf("%w: policy document exceeds %d bytes", core.ErrInvalidArgument, limits.MaxBytes)
	}
	// Decode into a wire shape first so EffectAllow strings can be validated
	// against the known enumeration before becoming core.Effect values.
	// "tests" is permitted for CLI fixtures and discarded here.
	var wire struct {
		Version   int64           `json:"version"`
		ID        string          `json:"id,omitempty"`
		Rules     []FileRule      `json:"rules"`
		UpdatedAt time.Time       `json:"updated_at,omitempty"`
		Hash      string          `json:"hash,omitempty"`
		Tests     json.RawMessage `json:"tests,omitempty"`
	}
	if err := strictDecode(raw, &wire); err != nil {
		return nil, fmt.Errorf("policy: invalid json: %w", err)
	}
	if wire.Rules == nil {
		return nil, fmt.Errorf("%w: rules array is required", core.ErrInvalidArgument)
	}
	if len(wire.Rules) > limits.MaxRules {
		return nil, fmt.Errorf("%w: rule count %d exceeds limit %d", core.ErrInvalidArgument, len(wire.Rules), limits.MaxRules)
	}
	id, err := boundString("id", wire.ID, limits.MaxStringLen)
	if err != nil {
		return nil, err
	}
	if id == "" {
		id = "default"
	}
	hash, err := boundString("hash", wire.Hash, limits.MaxStringLen)
	if err != nil {
		return nil, err
	}
	rules := make([]Rule, 0, len(wire.Rules))
	for i, fr := range wire.Rules {
		rule, err := fileRuleToRule(fr, limits)
		if err != nil {
			return nil, fmt.Errorf("policy: rule[%d]: %w", i, err)
		}
		normalized, err := normalizeRule(rule)
		if err != nil {
			return nil, fmt.Errorf("policy: rule[%d]: %w", i, err)
		}
		rules = append(rules, normalized)
	}
	return &Document{
		Version:   wire.Version,
		ID:        id,
		Rules:     rules,
		UpdatedAt: wire.UpdatedAt,
		Hash:      hash,
	}, nil
}

// Bytes marshals the document.
func (d *Document) Bytes() ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: nil document", core.ErrInvalidArgument)
	}
	return json.MarshalIndent(d, "", "  ")
}
