package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// ParseJSON parses raw JSON into policy rules with strict validation.
func ParseJSON(data []byte) ([]Rule, error) {
	return ParseJSONWithLimits(data, Limits{})
}

// ParseJSONWithLimits parses raw JSON with explicit resource bounds.
func ParseJSONWithLimits(data []byte, limits Limits) ([]Rule, error) {
	limits = limits.withDefaults()
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty policy document", core.ErrInvalidArgument)
	}
	if len(data) > limits.MaxBytes {
		return nil, fmt.Errorf("%w: policy document exceeds %d bytes", core.ErrInvalidArgument, limits.MaxBytes)
	}
	var pf PolicyFile
	if err := strictDecode(data, &pf); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	// Nil rules means deny-all (same as an empty array). Prefer "rules":[].
	if pf.Rules == nil {
		pf.Rules = []FileRule{}
	}
	if len(pf.Rules) > limits.MaxRules {
		return nil, fmt.Errorf("%w: rule count %d exceeds limit %d", core.ErrInvalidArgument, len(pf.Rules), limits.MaxRules)
	}
	rules := make([]Rule, 0, len(pf.Rules))
	for i, fr := range pf.Rules {
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
	return rules, nil
}

func fileRuleToRule(fr FileRule, limits Limits) (Rule, error) {
	principal, err := boundString("principal", fr.Principal, limits.MaxStringLen)
	if err != nil {
		return Rule{}, err
	}
	boundary, err := boundString("boundary", fr.Boundary, limits.MaxStringLen)
	if err != nil {
		return Rule{}, err
	}
	operation, err := boundString("operation", fr.Operation, limits.MaxStringLen)
	if err != nil {
		return Rule{}, err
	}
	if operation == "" {
		return Rule{}, fmt.Errorf("%w: operation required", core.ErrInvalidArgument)
	}
	version, err := boundString("operation_version", fr.OperationVersion, limits.MaxStringLen)
	if err != nil {
		return Rule{}, err
	}
	if version != "" {
		version = core.NormalizeOperationVersion(version)
		if version == "" {
			return Rule{}, fmt.Errorf("%w: invalid operation_version", core.ErrInvalidArgument)
		}
	}
	if len(fr.Permissions) > limits.MaxPermissions {
		return Rule{}, fmt.Errorf("%w: permissions exceed limit %d", core.ErrInvalidArgument, limits.MaxPermissions)
	}
	if len(fr.EffectAllow) > limits.MaxEffects {
		return Rule{}, fmt.Errorf("%w: effect_allow exceeds limit %d", core.ErrInvalidArgument, limits.MaxEffects)
	}
	permissions := make([]string, 0, len(fr.Permissions))
	for _, p := range fr.Permissions {
		p, err = boundString("permission", p, limits.MaxStringLen)
		if err != nil {
			return Rule{}, err
		}
		if p == "" {
			return Rule{}, fmt.Errorf("%w: empty permission", core.ErrInvalidArgument)
		}
		permissions = append(permissions, p)
	}
	effects := make([]core.Effect, 0, len(fr.EffectAllow))
	for _, e := range fr.EffectAllow {
		effect, err := validateEffect(e)
		if err != nil {
			return Rule{}, err
		}
		effects = append(effects, effect)
	}
	if fr.Priority < 0 {
		return Rule{}, fmt.Errorf("%w: priority cannot be negative", core.ErrInvalidArgument)
	}
	// Empty allow rules grant nothing useful and are almost always typos.
	if !fr.Deny && principal == "" && boundary == "" && operation == "*" && len(permissions) == 0 {
		return Rule{}, fmt.Errorf("%w: empty or global allow rule is not permitted", core.ErrInvalidArgument)
	}
	if strings.Contains(operation, " ") {
		return Rule{}, fmt.Errorf("%w: operation must not contain spaces", core.ErrInvalidArgument)
	}
	return Rule{
		Principal:        core.PrincipalID(principal),
		Boundary:         core.BoundaryID(boundary),
		Operation:        operation,
		OperationVersion: version,
		Permissions:      permissions,
		EffectAllow:      effects,
		Deny:             fr.Deny,
		Priority:         fr.Priority,
	}, nil
}

// LoadInto reads a policy file and atomically replaces all rules in the engine.
// On any parse or validation failure the previous engine state is preserved.
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
