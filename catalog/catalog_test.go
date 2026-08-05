package catalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/loreste/loom/core"
)

func regWith(t *testing.T, ops ...*core.Operation) *core.Registry {
	t.Helper()
	reg := core.NewRegistry()
	for _, op := range ops {
		if err := reg.Register(op, func(ec *core.ExecutionContext) (*core.Result, error) {
			return &core.Result{Output: map[string]any{}}, nil
		}); err != nil {
			t.Fatalf("register %s: %v", op.Name, err)
		}
	}
	return reg
}

func TestSpecOfFidelity(t *testing.T) {
	op := &core.Operation{
		Name:            "payment.capture",
		Description:     "Capture an authorized payment",
		InputSchema:     json.RawMessage(`{"type":"object"}`),
		Risk:            core.RiskHigh,
		Effects:         []core.Effect{core.EffectMoney, core.EffectWrite},
		Approval:        core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Idempotency:     core.IdempotencyPolicy{Required: true, TTLSeconds: 600},
		SensitiveFields: []string{"card"},
	}
	spec := SpecOf(op)
	if spec.Name != "payment.capture" || spec.Description == "" {
		t.Fatalf("identity fields lost: %+v", spec)
	}
	if spec.Risk != "high" {
		t.Fatalf("risk = %q, want high", spec.Risk)
	}
	if len(spec.Effects) != 2 || spec.Effects[0] != "money" {
		t.Fatalf("effects = %v", spec.Effects)
	}
	if spec.ApprovalRequired {
		t.Fatal("ApprovalRequired should be false when only MinRisk set")
	}
	if spec.ApprovalMinRisk != "high" {
		t.Fatalf("ApprovalMinRisk = %q", spec.ApprovalMinRisk)
	}
	if !spec.IdempotencyRequired {
		t.Fatal("IdempotencyRequired should be true")
	}
	if !spec.SensitiveFieldsPresent {
		t.Fatal("SensitiveFieldsPresent should be true")
	}
	// Adversarial: sensitive field NAMES must never appear in serialized spec.
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "card") {
		t.Fatalf("sensitive field name leaked in spec: %s", b)
	}
}

func TestBuildFiltersAndSorts(t *testing.T) {
	reg := regWith(t,
		&core.Operation{Name: "b.op", Permissions: []string{"b"}},
		&core.Operation{Name: "a.op", Permissions: []string{"a"}},
		&core.Operation{Name: "c.op", Permissions: []string{"c"}},
	)
	specs := Build(reg, func(op *core.Operation) bool { return op.Name != "b.op" })
	if len(specs) != 2 || specs[0].Name != "a.op" || specs[1].Name != "c.op" {
		t.Fatalf("got %+v", specs)
	}
}

func TestBuildNilFilterHidesEverything(t *testing.T) {
	reg := regWith(t, &core.Operation{Name: "x.op", Permissions: []string{"x"}})
	if specs := Build(reg, nil); specs != nil {
		t.Fatalf("nil include must hide all, got %+v", specs)
	}
	if specs := Build(nil, func(*core.Operation) bool { return true }); specs != nil {
		t.Fatalf("nil registry must yield nothing, got %+v", specs)
	}
}

func TestForCapabilities(t *testing.T) {
	reg := regWith(t,
		&core.Operation{Name: "doc.read", Permissions: []string{"document.read"}},
		&core.Operation{Name: "pay.capture", Permissions: []string{"payment.capture"}},
		&core.Operation{Name: "multi.op", Permissions: []string{"a", "b"}},
		&core.Operation{Name: "open.op"}, // no static permissions
	)
	specs := Build(reg, ForCapabilities([]string{"document.read", "a"}))
	if len(specs) != 1 || specs[0].Name != "doc.read" {
		t.Fatalf("capability filter leaked or hid wrong ops: %+v", specs)
	}
	// Both permissions held → visible.
	specs = Build(reg, ForCapabilities([]string{"a", "b"}))
	if len(specs) != 1 || specs[0].Name != "multi.op" {
		t.Fatalf("multi-permission op: %+v", specs)
	}
	// No capabilities → nothing.
	if specs := Build(reg, ForCapabilities(nil)); len(specs) != 0 {
		t.Fatalf("no caps must see nothing: %+v", specs)
	}
}

func TestDefaultManifestIsStatic(t *testing.T) {
	m := DefaultManifest("")
	if m.Service != "loom" || m.ExecuteEndpoint == "" || m.CatalogOperation != "catalog.spec" {
		t.Fatalf("bad manifest: %+v", m)
	}
	if len(m.Auth.Schemes) == 0 {
		t.Fatal("manifest must advertise auth schemes")
	}
	b, _ := json.Marshal(m)
	// Adversarial: manifest must never carry operation names beyond the catalog op.
	for _, leak := range []string{"payment.", "document.", "db.query"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("manifest leaked %q: %s", leak, b)
		}
	}
}
