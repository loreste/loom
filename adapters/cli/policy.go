package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

const maxPolicyInputBytes int64 = 16 << 20

type policyTestCase struct {
	Name         string   `json:"name"`
	Principal    string   `json:"principal"`
	Boundary     string   `json:"boundary"`
	Operation    string   `json:"operation"`
	Version      string   `json:"version,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Expected     string   `json:"expected"`
}

type policyTestDocument struct {
	Tests []policyTestCase `json:"tests"`
}

func loadPolicyDocument(path string) (*policy.Document, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("policy input path required")
	}
	file, err := os.Open(path) // #nosec G304 -- explicit offline operator input
	if err != nil {
		return nil, fmt.Errorf("unable to open policy input")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("unable to read policy input")
	}
	if int64(len(raw)) > maxPolicyInputBytes {
		return nil, fmt.Errorf("policy input exceeds size limit")
	}
	document, err := policy.ParseDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid policy document")
	}
	return document, nil
}

func lintPolicy(document *policy.Document) error {
	if document == nil || document.Version <= 0 {
		return fmt.Errorf("policy version must be positive")
	}
	engine := policy.NewMemoryEngine()
	if err := engine.ReplaceRules(document.Rules); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) runPolicyLint(args []string) int {
	flags := parseFlags(args)
	document, err := loadPolicyDocument(flags["input"])
	if err == nil {
		err = lintPolicy(document)
	}
	if err != nil {
		fmt.Fprintln(a.errW(), "policy lint:", err)
		return 1
	}
	result := map[string]any{"valid": true, "version": document.Version, "rule_count": len(document.Rules)}
	if document.ID != "" {
		result["id"] = document.ID
	}
	return writeJSON(a.outW(), result, a.errW(), "policy lint")
}

// runPolicyTest evaluates explicit, bounded policy fixtures embedded in the
// policy document under "tests". Test inputs are operator-authored and are
// never treated as authorization grants by the runtime.
func (a *Adapter) runPolicyTest(args []string) int {
	flags := parseFlags(args)
	path := strings.TrimSpace(flags["input"])
	document, err := loadPolicyDocument(path)
	if err != nil {
		fmt.Fprintln(a.errW(), "policy test:", err)
		return 1
	}
	file, err := os.Open(path) // #nosec G304 -- explicit offline operator input
	if err != nil {
		fmt.Fprintln(a.errW(), "policy test: unable to read input")
		return 1
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyInputBytes+1))
	if err != nil || int64(len(raw)) > maxPolicyInputBytes {
		fmt.Fprintln(a.errW(), "policy test: input exceeds size limit")
		return 1
	}
	var fixture policyTestDocument
	if err := json.Unmarshal(raw, &fixture); err != nil {
		fmt.Fprintln(a.errW(), "policy test: invalid test fixture")
		return 1
	}
	if len(fixture.Tests) > 10_000 {
		fmt.Fprintln(a.errW(), "policy test: test limit exceeded")
		return 1
	}
	engine := policy.NewMemoryEngine()
	if err := engine.ReplaceRules(document.Rules); err != nil {
		fmt.Fprintln(a.errW(), "policy test:", err)
		return 1
	}
	failed := make([]string, 0)
	for index, test := range fixture.Tests {
		name := test.Name
		if name == "" {
			name = fmt.Sprintf("test-%d", index+1)
		}
		version := test.Version
		if version == "" {
			version = core.DefaultOperationVersion
		}
		identity := core.Identity{ID: core.PrincipalID(test.Principal), Boundary: core.BoundaryID(test.Boundary), Capabilities: test.Capabilities}
		op := &core.Operation{Name: test.Operation, Version: version}
		decision := engine.CheckOperationPermission(context.Background(), identity, op)
		wantAllow := strings.EqualFold(strings.TrimSpace(test.Expected), "allow")
		if (decision.Decision == core.DecisionAllow) != wantAllow {
			failed = append(failed, name)
		}
	}
	result := map[string]any{"valid": len(failed) == 0, "version": document.Version, "test_count": len(fixture.Tests), "failed": failed}
	status := writeJSON(a.outW(), result, a.errW(), "policy test")
	if status != 0 {
		return status
	}
	if len(failed) > 0 {
		return 1
	}
	return 0
}

func (a *Adapter) runPolicyExplain(args []string, simulate bool) int {
	flags := parseFlags(args)
	document, err := loadPolicyDocument(flags["input"])
	if err == nil {
		err = lintPolicy(document)
	}
	if err != nil {
		fmt.Fprintln(a.errW(), "policy explain:", err)
		return 1
	}
	principal := strings.TrimSpace(flags["principal"])
	boundary := strings.TrimSpace(flags["boundary"])
	operation := strings.TrimSpace(flags["operation"])
	if principal == "" || boundary == "" || operation == "" {
		fmt.Fprintln(a.errW(), "policy explain requires --principal, --boundary, and --operation")
		return 2
	}
	version := strings.TrimSpace(flags["version"])
	if version == "" {
		version = core.DefaultOperationVersion
	}
	capabilities := splitCSV(flags["capabilities"])
	identity := core.Identity{ID: core.PrincipalID(principal), Boundary: core.BoundaryID(boundary), Capabilities: capabilities}
	op := &core.Operation{Name: operation, Version: version}
	engine := policy.NewMemoryEngine()
	if err := engine.ReplaceRules(document.Rules); err != nil {
		fmt.Fprintln(a.errW(), "policy explain:", err)
		return 1
	}
	permission := engine.CheckOperationPermission(context.Background(), identity, op)
	request := &core.Request{Operation: operation, OperationVersion: version, Boundary: core.BoundaryID(boundary)}
	contextual := engine.EvaluateContextual(context.Background(), identity, core.BoundaryID(boundary), op, request)
	result := map[string]any{
		"mode":              map[bool]string{true: "simulate", false: "explain"}[simulate],
		"principal":         principal,
		"boundary":          boundary,
		"operation":         operation,
		"operation_version": version,
		"permission":        permission.Decision.String(),
		"permission_reason": permission.Reason,
		"contextual":        contextual.Decision.String(),
		"contextual_reason": contextual.Reason,
		"allowed":           permission.Decision == core.DecisionAllow && contextual.Decision == core.DecisionAllow,
	}
	return writeJSON(a.outW(), result, a.errW(), "policy explain")
}

func (a *Adapter) runPolicyDiff(args []string) int {
	flags := parseFlags(args)
	left, err := loadPolicyDocument(flags["from"])
	if err == nil {
		err = lintPolicy(left)
	}
	right, rightErr := loadPolicyDocument(flags["to"])
	if err == nil {
		err = rightErr
	}
	if err == nil {
		err = lintPolicy(right)
	}
	if err != nil {
		fmt.Fprintln(a.errW(), "policy diff:", err)
		return 1
	}
	leftRules := policyRuleKeys(left.Rules)
	rightRules := policyRuleKeys(right.Rules)
	added := difference(rightRules, leftRules)
	removed := difference(leftRules, rightRules)
	result := map[string]any{"from_version": left.Version, "to_version": right.Version, "added": added, "removed": removed}
	return writeJSON(a.outW(), result, a.errW(), "policy diff")
}

func policyRuleKeys(rules []policy.Rule) []string {
	keys := make([]string, 0, len(rules))
	for _, rule := range rules {
		encoded, _ := json.Marshal(rule)
		digest := sha256.Sum256(encoded)
		keys = append(keys, hex.EncodeToString(digest[:]))
	}
	sort.Strings(keys)
	return keys
}

func difference(left, right []string) []string {
	set := make(map[string]struct{}, len(right))
	for _, value := range right {
		set[value] = struct{}{}
	}
	result := make([]string, 0)
	for _, value := range left {
		if _, ok := set[value]; !ok {
			result = append(result, value)
		}
	}
	return result
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func writeJSON(out io.Writer, value any, errOut io.Writer, label string) int {
	if err := json.NewEncoder(out).Encode(value); err != nil {
		fmt.Fprintln(errOut, label+": output failed")
		return 1
	}
	return 0
}
