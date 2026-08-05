package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
)

func TestHealthAndExecute(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{Addr: ":0"})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// health
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Code)
	}

	// unauthenticated execute
	body := `{"operation":"document.read","boundary":"dev","input":{"id":"1"},"resource":{"type":"document","id":"1"}}`
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code %d body %s", rr.Code, rr.Body.String())
	}

	// authenticated
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("code %d body %s", rr.Code, rr.Body.String())
	}
	var resp core.Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
	// sensitive stripped
	if _, ok := resp.Output["internal_notes"]; ok {
		t.Fatal("leaked internal_notes")
	}

	// bypass header
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	req.Header.Set("X-Loom-Bypass", "true")
	h.ServeHTTP(rr, req)
	if rr.Code == 200 {
		t.Fatal("bypass must not succeed")
	}

	// body too large
	rr = httptest.NewRecorder()
	big := bytes.Repeat([]byte("a"), 2<<20)
	req = httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(big))
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 got %d", rr.Code)
	}

	// TRACE rejected
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodTrace, "/v1/execute", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("trace: %d", rr.Code)
	}
}

func TestJWTAuthOverHTTP(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := p.MintDemoJWT("user:alice", "dev", []string{"document.read", "document.write"}, "user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{})
	body := `{"operation":"document.read","boundary":"dev","input":{"id":"x"},"resource":{"type":"document","id":"x"}}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestPaymentFlowHTTP(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.IssueApproval("appr-pay-1", "user:bob", "payment.capture", "dev", core.RiskCritical, time.Hour); err != nil {
		t.Fatal(err)
	}
	srv, _ := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{})
	payload := map[string]any{
		"operation": "payment.capture",
		"boundary":  "dev",
		"resource":  map[string]string{"type": "payment", "id": "p1"},
		"input": map[string]any{
			"amount":      42.5,
			"currency":    "USD",
			"merchant_id": "m_1",
		},
		"idempotency_key": "idem-http-1",
		"approval_token":  "appr-pay-1",
	}
	b, _ := json.Marshal(payload)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer bob-finance-token")
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	var resp core.Response
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.Allowed {
		t.Fatal(resp.Denial)
	}
	if _, ok := resp.Output["raw_processor_payload"]; ok {
		t.Fatal("processor payload must not leak")
	}
	// replay
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer bob-finance-token")
	srv.Handler().ServeHTTP(rr, req)
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !resp.IdempotentReplay {
		t.Fatal("expected replay")
	}
}

func TestMTLSCredentialsPath(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// Direct runtime path with mtls scheme (HTTP layer needs real TLS for cert extract;
	// verify multi verifier accepts mtls credentials).
	_ = p.IssueApproval("appr-mtls", "svc:payments", "payment.capture", "dev", core.RiskCritical, time.Hour)
	resp := p.Runtime.Execute(context.Background(), core.Request{
		Operation: "payment.capture",
		Credentials: core.Credentials{
			Scheme: "mtls",
			Token:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		},
		Boundary: "dev",
		Resource: &core.ResourceRef{Type: "payment", ID: "p2"},
		Input: map[string]any{
			"amount": 10.0, "currency": "USD", "merchant_id": "m",
		},
		IdempotencyKey: "idem-mtls",
		ApprovalToken:  "appr-mtls",
	})
	if !resp.Allowed {
		t.Fatalf("%+v", resp.Denial)
	}
}

func TestSecurityHeaders(t *testing.T) {
	p, _ := bootstrap.NewPlatform(bootstrap.Config{})
	srv, _ := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing frame deny")
	}
}

func TestDiscoveryManifest(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	// Unauthenticated: manifest must be served without credentials…
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/.well-known/loom.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d body %s", rr.Code, rr.Body.String())
	}
	body1 := rr.Body.String()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["service"] != "loom" || m["execute_endpoint"] == "" || m["catalog_operation"] != "catalog.spec" {
		t.Fatalf("bad manifest: %s", body1)
	}
	// …and must be identical regardless of caller (static, no per-caller data).
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/loom.json", nil)
	req.Header.Set("Authorization", "Bearer alice-secret-token")
	h.ServeHTTP(rr, req)
	if rr.Body.String() != body1 {
		t.Fatal("manifest must be static regardless of auth")
	}
	// Adversarial: no operation names beyond the catalog op.
	for _, leak := range []string{"payment.capture", "document.read", "db.query", "approval.issue"} {
		if strings.Contains(body1, leak) {
			t.Fatalf("manifest leaked %q: %s", leak, body1)
		}
	}

	// Root pointer mentions the manifest.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rr.Body.String(), "/.well-known/loom.json") {
		t.Fatalf("root must point at manifest: %s", rr.Body.String())
	}
}
