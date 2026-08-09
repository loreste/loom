package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loreste/loom/core"
)

// FileRule is the JSON-serializable form of a policy rule.
type FileRule struct {
	Principal        string   `json:"principal,omitempty"`
	Boundary         string   `json:"boundary,omitempty"`
	Operation        string   `json:"operation"`
	OperationVersion string   `json:"operation_version,omitempty"`
	Permissions      []string `json:"permissions,omitempty"`
	EffectAllow      []string `json:"effect_allow,omitempty"`
	Deny             bool     `json:"deny,omitempty"`
	Priority         int      `json:"priority,omitempty"`
}

// PolicyFile is the top-level structure of a policy JSON file.
type PolicyFile struct {
	Rules []FileRule `json:"rules"`
}

// LoadFile reads a JSON policy file and returns parsed rules.
func LoadFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return ParseJSON(data)
}

// ParseJSON parses raw JSON into policy rules.
func ParseJSON(data []byte) ([]Rule, error) {
	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	rules := make([]Rule, len(pf.Rules))
	for i, fr := range pf.Rules {
		effects := make([]core.Effect, len(fr.EffectAllow))
		for j, e := range fr.EffectAllow {
			effects[j] = core.Effect(e)
		}
		rules[i] = Rule{
			Principal:        core.PrincipalID(fr.Principal),
			Boundary:         core.BoundaryID(fr.Boundary),
			Operation:        fr.Operation,
			OperationVersion: fr.OperationVersion,
			Permissions:      fr.Permissions,
			EffectAllow:      effects,
			Deny:             fr.Deny,
			Priority:         fr.Priority,
		}
	}
	return rules, nil
}

// LoadInto reads a policy file and atomically replaces all rules in the engine.
func LoadInto(engine *MemoryEngine, path string) error {
	rules, err := LoadFile(path)
	if err != nil {
		return err
	}
	return engine.ReplaceRules(rules)
}

// MarshalRules serializes rules to JSON for export or inspection.
func MarshalRules(rules []Rule) ([]byte, error) {
	pf := PolicyFile{Rules: make([]FileRule, len(rules))}
	for i, r := range rules {
		effects := make([]string, len(r.EffectAllow))
		for j, e := range r.EffectAllow {
			effects[j] = string(e)
		}
		pf.Rules[i] = FileRule{
			Principal:        string(r.Principal),
			Boundary:         string(r.Boundary),
			Operation:        r.Operation,
			OperationVersion: r.OperationVersion,
			Permissions:      r.Permissions,
			EffectAllow:      effects,
			Deny:             r.Deny,
			Priority:         r.Priority,
		}
	}
	return json.MarshalIndent(pf, "", "  ")
}
