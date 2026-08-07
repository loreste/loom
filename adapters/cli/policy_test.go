package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loreste/loom/policy"
)

func writePolicyFixture(t *testing.T, document policy.Document) string {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPolicyLintExplainAndSimulate(t *testing.T) {
	path := writePolicyFixture(t, policy.Document{Version: 3, ID: "tenant-policy", Rules: []policy.Rule{{
		Principal: "user:alice", Boundary: "dev", Operation: "document.read", Priority: 10,
	}}})
	for _, test := range []struct {
		name string
		args []string
		call func(*Adapter, []string) int
		want string
	}{
		{name: "lint", args: []string{"--input=" + path}, call: (*Adapter).runPolicyLint, want: `"valid":true`},
		{name: "explain", args: []string{"--input=" + path, "--principal=user:alice", "--boundary=dev", "--operation=document.read"}, call: func(a *Adapter, args []string) int { return a.runPolicyExplain(args, false) }, want: `"allowed":true`},
		{name: "simulate", args: []string{"--input=" + path, "--principal=user:bob", "--boundary=dev", "--operation=document.read"}, call: func(a *Adapter, args []string) int { return a.runPolicyExplain(args, true) }, want: `"allowed":false`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			a := New(nil)
			a.Out = &out
			a.Err = &errOut
			if got := test.call(a, test.args); got != 0 {
				t.Fatalf("command = %d, stderr=%s", got, errOut.String())
			}
			if !strings.Contains(out.String(), test.want) {
				t.Fatalf("output = %q, want %q", out.String(), test.want)
			}
		})
	}
}

func TestPolicyLintRejectsGlobalWildcardAllow(t *testing.T) {
	path := writePolicyFixture(t, policy.Document{Version: 1, Rules: []policy.Rule{{Operation: "*", Priority: 100}}})
	var out, errOut bytes.Buffer
	a := New(nil)
	a.Out = &out
	a.Err = &errOut
	if got := a.runPolicyLint([]string{"--input=" + path}); got == 0 {
		t.Fatal("global wildcard policy unexpectedly linted successfully")
	}
}

func TestPolicyDiffReportsChangedRuleHashes(t *testing.T) {
	from := writePolicyFixture(t, policy.Document{Version: 1, Rules: []policy.Rule{{Principal: "user:alice", Boundary: "dev", Operation: "document.read"}}})
	to := writePolicyFixture(t, policy.Document{Version: 2, Rules: []policy.Rule{{Principal: "user:alice", Boundary: "dev", Operation: "document.write"}}})
	var out, errOut bytes.Buffer
	a := New(nil)
	a.Out = &out
	a.Err = &errOut
	if got := a.runPolicyDiff([]string{"--from=" + from, "--to=" + to}); got != 0 {
		t.Fatalf("policy diff = %d, stderr=%s", got, errOut.String())
	}
	if !strings.Contains(out.String(), `"added"`) || !strings.Contains(out.String(), `"removed"`) {
		t.Fatalf("diff output = %q", out.String())
	}
}

func TestPolicyTestRunsExplicitFixtures(t *testing.T) {
	raw := `{"version":4,"rules":[{"principal":"user:alice","boundary":"dev","operation":"document.read"}],"tests":[{"name":"allowed","principal":"user:alice","boundary":"dev","operation":"document.read","expected":"allow"},{"name":"denied","principal":"user:bob","boundary":"dev","operation":"document.read","expected":"deny"}]}`
	path := filepath.Join(t.TempDir(), "policy-tests.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)
	a := New(nil)
	a.Out, a.Err = out, errOut
	if got := a.runPolicyTest([]string{"--input=" + path}); got != 0 {
		t.Fatalf("runPolicyTest() = %d, stderr=%s", got, errOut.String())
	}
	if !strings.Contains(out.String(), `"valid":true`) {
		t.Fatalf("policy test output = %q", out.String())
	}
}
