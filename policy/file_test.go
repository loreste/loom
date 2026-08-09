package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseJSON(t *testing.T) {
	data := []byte(`{
		"rules": [
			{
				"principal": "alice",
				"boundary": "acme",
				"operation": "document.read",
				"permissions": ["document.read"],
				"effect_allow": ["read"]
			},
			{
				"operation": "admin.reset",
				"deny": true,
				"priority": 100
			}
		]
	}`)
	rules, err := ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Principal != "alice" {
		t.Fatalf("expected principal alice, got %q", rules[0].Principal)
	}
	if rules[0].Operation != "document.read" {
		t.Fatalf("expected operation document.read, got %q", rules[0].Operation)
	}
	if len(rules[0].EffectAllow) != 1 || string(rules[0].EffectAllow[0]) != "read" {
		t.Fatalf("expected effect_allow [read], got %v", rules[0].EffectAllow)
	}
	if !rules[1].Deny {
		t.Fatal("expected deny rule")
	}
	if rules[1].Priority != 100 {
		t.Fatalf("expected priority 100, got %d", rules[1].Priority)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := []byte(`{"rules":[{"operation":"test.op","principal":"bob","boundary":"org1","permissions":["test"]}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Operation != "test.op" {
		t.Fatalf("unexpected rules: %v", rules)
	}
}

func TestLoadInto(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data := []byte(`{"rules":[{"principal":"eve","boundary":"b1","operation":"doc.read","permissions":["doc.read"]}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	engine := NewMemoryEngine()
	// Pre-populate to verify replacement
	engine.AddRule(Rule{Operation: "old.op", Principal: "old"})
	if engine.RuleCount() != 1 {
		t.Fatal("expected 1 pre-existing rule")
	}
	if err := LoadInto(engine, path); err != nil {
		t.Fatal(err)
	}
	if engine.RuleCount() != 1 {
		t.Fatalf("expected 1 rule after load, got %d", engine.RuleCount())
	}
	snap := engine.Snapshot()
	if snap[0].Operation != "doc.read" {
		t.Fatalf("expected doc.read, got %q", snap[0].Operation)
	}
}

func TestLoadFileMissing(t *testing.T) {
	_, err := LoadFile("/nonexistent/policy.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseJSONInvalid(t *testing.T) {
	_, err := ParseJSON([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	original := []byte(`{"rules":[{"principal":"alice","boundary":"acme","operation":"doc.read","permissions":["doc.read"],"effect_allow":["read"]}]}`)
	rules, err := ParseJSON(original)
	if err != nil {
		t.Fatal(err)
	}
	out, err := MarshalRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	roundtripped, err := ParseJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(roundtripped) != len(rules) {
		t.Fatalf("roundtrip lost rules: %d → %d", len(rules), len(roundtripped))
	}
	if roundtripped[0].Operation != rules[0].Operation {
		t.Fatalf("roundtrip changed operation: %q → %q", rules[0].Operation, roundtripped[0].Operation)
	}
}
