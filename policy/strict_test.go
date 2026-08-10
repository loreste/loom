package policy

import (
	"os"
	"strings"
	"sync"
	"testing"
)

func TestParseJSONRejectsUnknownFields(t *testing.T) {
	_, err := ParseJSON([]byte(`{"rules":[{"operation":"doc.read","principal":"a","allow":true}]}`))
	if err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestParseJSONRejectsDuplicateKeys(t *testing.T) {
	// Duplicate "operation" at rule level must fail closed.
	raw := []byte(`{"rules":[{"operation":"doc.read","operation":"admin.reset","principal":"a","boundary":"b"}]}`)
	if _, err := ParseJSON(raw); err == nil {
		t.Fatal("duplicate JSON keys must be rejected")
	}
}

func TestParseJSONRejectsTrailingJSON(t *testing.T) {
	raw := []byte(`{"rules":[{"operation":"doc.read","principal":"a","boundary":"b"}]}{"rules":[]}`)
	if _, err := ParseJSON(raw); err == nil {
		t.Fatal("trailing JSON must be rejected")
	}
}

func TestParseJSONRejectsInvalidEffects(t *testing.T) {
	raw := []byte(`{"rules":[{"operation":"doc.read","principal":"a","boundary":"b","effect_allow":["read","explode"]}]}`)
	if _, err := ParseJSON(raw); err == nil {
		t.Fatal("invalid effect must be rejected")
	}
}

func TestParseJSONRejectsOversizedDocument(t *testing.T) {
	raw := []byte(`{"rules":[` + strings.Repeat(`{"operation":"doc.read","principal":"a","boundary":"b"},`, 50) + `{"operation":"doc.read","principal":"a","boundary":"b"}]}`)
	_, err := ParseJSONWithLimits(raw, Limits{MaxBytes: 64})
	if err == nil {
		t.Fatal("oversized document must be rejected")
	}
}

func TestParseJSONRejectsGlobalWildcardAllow(t *testing.T) {
	raw := []byte(`{"rules":[{"operation":"*"}]}`)
	if _, err := ParseJSON(raw); err == nil {
		t.Fatal("global wildcard allow must be rejected")
	}
}

func TestLoadIntoPreservesActivePolicyOnInvalidReload(t *testing.T) {
	dir := t.TempDir()
	good := dir + "/good.json"
	bad := dir + "/bad.json"
	if err := writeFile(good, `{"rules":[{"operation":"doc.read","principal":"alice","boundary":"dev","permissions":["doc.read"]}]}`); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(bad, `{"rules":[{"operation":"doc.read","principal":"alice","boundary":"dev","effect_allow":["nope"]}]}`); err != nil {
		t.Fatal(err)
	}
	engine := NewMemoryEngine()
	if err := LoadInto(engine, good); err != nil {
		t.Fatal(err)
	}
	if engine.RuleCount() != 1 {
		t.Fatalf("RuleCount = %d", engine.RuleCount())
	}
	if err := LoadInto(engine, bad); err == nil {
		t.Fatal("invalid reload must fail")
	}
	if engine.RuleCount() != 1 {
		t.Fatalf("active policy mutated on failed reload: count=%d", engine.RuleCount())
	}
	snap := engine.Snapshot()
	if snap[0].Principal != "alice" {
		t.Fatalf("active rule changed: %+v", snap[0])
	}
}

func TestParseJSONConcurrent(t *testing.T) {
	raw := []byte(`{"rules":[{"operation":"doc.read","principal":"alice","boundary":"dev","permissions":["doc.read"],"effect_allow":["read"]}]}`)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ParseJSON(raw)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvalidPolicyNeverExpandsPermissions(t *testing.T) {
	// Property: any document that fails ParseJSON leaves engine deny-all when
	// ReplaceRules is only called on success.
	engine := NewMemoryEngine()
	before := engine.RuleCount()
	invalids := []string{
		`{"rules":[{"operation":"*"}]}`,
		`{"rules":[{"operation":"x","effect_allow":["money","wat"]}]}`,
		`{"rules":[{"operation":"x"}],"extra":1}`,
		`{"rules":[{"operation":"x","priority":-1,"principal":"a","boundary":"b"}]}`,
		`{"rules":[{"operation":"x","permissions":[""],"principal":"a","boundary":"b"}]}`,
	}
	for _, raw := range invalids {
		rules, err := ParseJSON([]byte(raw))
		if err == nil {
			t.Fatalf("expected rejection for %s", raw)
		}
		if rules != nil {
			t.Fatalf("rejected parse must return nil rules for %s", raw)
		}
		if engine.RuleCount() != before {
			t.Fatal("engine mutated without ReplaceRules")
		}
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
