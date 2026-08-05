package guardrails_test

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/guardrails"
)

func netReq(v string) *core.Request {
	return &core.Request{Input: map[string]any{"url": v}}
}

func TestNetworkGuardSSRFUserinfoBypass(t *testing.T) {
	g := guardrails.NetworkGuard{SkipDNS: true}
	attempts := []string{
		"http://user@169.254.169.254/latest/meta-data",
		"http://evil.com@169.254.169.254/",
		"http://user:pass@127.0.0.1:8080/admin",
		"user@127.0.0.1",
	}
	for _, a := range attempts {
		res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, netReq(a))
		if res.OK {
			t.Errorf("SSRF attempt %q was allowed", a)
		}
	}
}

func TestNetworkGuardNonDottedIPBypass(t *testing.T) {
	g := guardrails.NetworkGuard{SkipDNS: true}
	attempts := []string{
		"http://2130706433/",         // 127.0.0.1 as decimal
		"http://0177.0.0.1/",         // octal quad
		"http://0x7f.0.0.1/",         // hex quad
		"http://127.1/",              // shortened loopback
		"http://2852039166/",         // 169.254.169.254 as decimal
		"http://[::ffff:127.0.0.1]/", // IPv4-mapped IPv6 loopback
		"http://[::1]/",
		"2130706433",
	}
	for _, a := range attempts {
		res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, netReq(a))
		if res.OK {
			t.Errorf("non-dotted IP attempt %q was allowed", a)
		}
	}
}

func TestNetworkGuardMalformedURLFailsClosed(t *testing.T) {
	g := guardrails.NetworkGuard{SkipDNS: true}
	res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, netReq("http://"))
	if res.OK {
		t.Fatal("URL claiming a scheme but no host must fail closed")
	}
}

func TestNetworkGuardPublicStillAllowed(t *testing.T) {
	// SkipDNS: public hostname form is allowed when not resolving.
	g := guardrails.NetworkGuard{SkipDNS: true}
	res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, netReq("https://example.com/path?q=1"))
	if !res.OK {
		t.Fatalf("public host denied: %s", res.Message)
	}
}

type fakeResolver struct {
	addrs map[string][]net.IPAddr
	err   error
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.addrs[host], nil
}

func TestNetworkGuardDNSRebindingBlocked(t *testing.T) {
	g := guardrails.NetworkGuard{
		Resolver: fakeResolver{addrs: map[string][]net.IPAddr{
			"evil.example": {{IP: net.ParseIP("169.254.169.254")}},
		}},
	}
	res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, netReq("https://evil.example/meta"))
	if res.OK {
		t.Fatal("DNS rebinding to metadata IP must be blocked")
	}
}

func TestNetworkGuardDNSErrorFailsClosed(t *testing.T) {
	g := guardrails.NetworkGuard{
		Resolver: fakeResolver{err: context.DeadlineExceeded},
	}
	res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, netReq("https://unknown.example/"))
	if res.OK {
		t.Fatal("DNS failure must fail closed")
	}
}

func TestNetworkGuardNestedWebhookField(t *testing.T) {
	g := guardrails.NetworkGuard{SkipDNS: true}
	req := &core.Request{Input: map[string]any{
		"config": map[string]any{"url": "http://127.0.0.1/hook"},
	}}
	res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, req)
	if res.OK {
		t.Fatal("nested private url must be blocked")
	}
}

func TestRedactSecretsNestedSlices(t *testing.T) {
	m := guardrails.RedactSecrets(map[string]any{
		"tokens": []any{"sk-abcdefghijklmnopqrstuvwxyz", "ok"},
		"keys":   []string{"ghp_abcdefghijklmnopqrstuvwxyz", "fine"},
		"deep":   []any{[]any{"sk-abcdefghijklmnopqrstuvwxyz"}},
		"nested": map[string]any{"list": []any{"xoxb-1234567890-abc"}},
	})
	toks := m["tokens"].([]any)
	if toks[0] != "[REDACTED]" || toks[1] != "ok" {
		t.Fatalf("[]any not redacted: %v", toks)
	}
	keys := m["keys"].([]string)
	if keys[0] != "[REDACTED]" || keys[1] != "fine" {
		t.Fatalf("[]string not redacted: %v", keys)
	}
	if m["deep"].([]any)[0].([]any)[0] != "[REDACTED]" {
		t.Fatalf("deeply nested slice not redacted: %v", m["deep"])
	}
	if m["nested"].(map[string]any)["list"].([]any)[0] != "[REDACTED]" {
		t.Fatalf("slice in nested map not redacted: %v", m["nested"])
	}
}

func TestSecretGuardFlagsSecretsInSlices(t *testing.T) {
	g := guardrails.SecretGuard{}
	req := &core.Request{Input: map[string]any{
		"tokens": []any{"sk-abcdefghijklmnopqrstuvwxyz"},
	}}
	res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, req)
	if res.OK {
		t.Fatal("secret inside []any must be flagged")
	}
	req2 := &core.Request{Input: map[string]any{
		"keys": []string{"ghp_abcdefghijklmnopqrstuvwxyz"},
	}}
	if res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, req2); res.OK {
		t.Fatal("secret inside []string must be flagged")
	}
	clean := &core.Request{Input: map[string]any{"tokens": []any{"hello", "world"}}}
	if res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, clean); !res.OK {
		t.Fatalf("clean slices flagged: %s", res.Message)
	}
}

func TestFilesystemGuardPrefixBoundary(t *testing.T) {
	g := guardrails.FilesystemGuard{AllowedPrefixes: []string{"/data"}}
	req := &core.Request{Input: map[string]any{"path": "/data2/secret"}}
	if res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, req); res.OK {
		t.Fatal("/data2/secret must not match prefix /data")
	}
	for _, ok := range []string{"/data", "/data/file.txt", "/data/sub/dir"} {
		req := &core.Request{Input: map[string]any{"path": ok}}
		if res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, req); !res.OK {
			t.Errorf("legit path %q denied: %s", ok, res.Message)
		}
	}
	// Trailing-slash prefixes behave the same.
	g2 := guardrails.FilesystemGuard{AllowedPrefixes: []string{"/data/"}}
	req = &core.Request{Input: map[string]any{"path": "/data2/secret"}}
	if res := g2.Check(context.Background(), core.Identity{}, &core.Operation{}, req); res.OK {
		t.Fatal("/data2/secret must not match prefix /data/")
	}
}

func TestFinancialGuardZeroValueDeniesMoney(t *testing.T) {
	op := &core.Operation{Effects: []core.Effect{core.EffectMoney}}
	req := &core.Request{Input: map[string]any{"amount": float64(1)}}
	// Zero-value guard must fail closed, not unlimited.
	g := &guardrails.FinancialGuard{}
	if res := g.Check(context.Background(), core.Identity{}, op, req); res.OK {
		t.Fatal("zero-value FinancialGuard must deny money operations")
	}
	// Explicit opt-in still allows.
	g2 := &guardrails.FinancialGuard{Unlimited: true}
	if res := g2.Check(context.Background(), core.Identity{}, op, req); !res.OK {
		t.Fatalf("Unlimited opt-in denied: %s", res.Message)
	}
	// Configured limits unchanged.
	g3 := &guardrails.FinancialGuard{MaxAmount: 100}
	if res := g3.Check(context.Background(), core.Identity{}, op, req); !res.OK {
		t.Fatalf("within-limit denied: %s", res.Message)
	}
	big := &core.Request{Input: map[string]any{"amount": float64(101)}}
	if res := g3.Check(context.Background(), core.Identity{}, op, big); res.OK {
		t.Fatal("over-limit allowed")
	}
	// Non-money ops unaffected by zero value.
	if res := g.Check(context.Background(), core.Identity{}, &core.Operation{}, req); !res.OK {
		t.Fatal("non-money op must pass")
	}
}

func TestSchemaPatternCacheDeniesBadPatterns(t *testing.T) {
	op := &core.Operation{
		InputSchema: []byte(`{"type":"object","properties":{"id":{"type":"string","pattern":"[unclosed"}}}`),
	}
	req := &core.Request{Input: map[string]any{"id": "x"}}
	res := guardrails.SchemaGuard{}.Check(context.Background(), core.Identity{}, op, req)
	if res.OK {
		t.Fatal("invalid pattern must deny")
	}
	// Overlong pattern must deny.
	long := strings.Repeat("a", 300)
	op2 := &core.Operation{
		InputSchema: []byte(`{"type":"object","properties":{"id":{"type":"string","pattern":"` + long + `"}}}`),
	}
	if res := (guardrails.SchemaGuard{}).Check(context.Background(), core.Identity{}, op2, req); res.OK {
		t.Fatal("overlong pattern must deny")
	}
	// Valid cached pattern works twice.
	op3 := &core.Operation{
		InputSchema: []byte(`{"type":"object","properties":{"id":{"type":"string","pattern":"^[a-z]+$"}}}`),
	}
	req3 := &core.Request{Input: map[string]any{"id": "abc"}}
	for i := 0; i < 2; i++ {
		if res := (guardrails.SchemaGuard{}).Check(context.Background(), core.Identity{}, op3, req3); !res.OK {
			t.Fatalf("valid pattern denied on iteration %d: %s", i, res.Message)
		}
	}
}
