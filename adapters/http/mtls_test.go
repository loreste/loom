package http_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/internal/tlstest"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/resource"
)

func TestMTLSEndToEndPayment(t *testing.T) {
	bundle, err := tlstest.Generate()
	if err != nil {
		t.Fatal(err)
	}

	p, err := bootstrap.NewPlatform(bootstrap.Config{})
	if err != nil {
		t.Fatal(err)
	}

	// Map real client cert → svc:mtls-pay with grants
	fp := bundle.ClientFingerprint
	if err := p.MTLS.Register(identity.CertPrincipal{
		FingerprintSHA256: fp,
		ID:                "svc:mtls-pay",
		Type:              "service",
		Boundary:          "dev",
		Capabilities:      []string{"payment.capture"},
	}); err != nil {
		t.Fatal(err)
	}
	_ = p.Boundary.Grant("svc:mtls-pay", "dev")
	_ = p.Policy.AddRule(policy.Rule{
		Principal: "svc:mtls-pay",
		Boundary:  "dev",
		Operation: "payment.capture",
		Priority:  10,
	})
	_ = p.Resources.Grant(resource.Rule{
		Principal:  "svc:mtls-pay",
		Boundary:   "dev",
		Type:       "payment",
		ID:         "*",
		Operations: []string{"payment.capture"},
	})
	_ = p.Fields.GrantFields("svc:mtls-pay", "dev", "payment.capture", []string{"*"})
	_ = p.IssueApproval("mtls-appr", "svc:mtls-pay", "payment.capture", "dev", core.RiskCritical, time.Hour)

	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{
		TLSConfig:   bundle.ServerTLSConfig(),
		RequireMTLS: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = bundle.ServerTLSConfig()
	ts.StartTLS()
	defer ts.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: bundle.ClientTLSConfig(),
		},
	}

	payload := map[string]any{
		"operation": "payment.capture",
		"boundary":  "dev",
		"resource":  map[string]string{"type": "payment", "id": "mtls-1"},
		"input": map[string]any{
			"amount": 3.5, "currency": "USD", "merchant_id": "m",
		},
		"idempotency_key": "mtls-idem-1",
		"approval_token":  "mtls-appr",
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/execute", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization — mTLS only
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		t.Fatalf("status %d body %s", res.StatusCode, body)
	}
	var resp core.Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Allowed {
		t.Fatalf("denied: %+v", resp.Denial)
	}

	// Without client cert must fail TLS handshake or be rejected
	badClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    bundle.ClientTLSConfig().RootCAs,
				ServerName: "localhost",
				// no client cert
			},
		},
	}
	// request body was consumed — rebuild
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/execute", bytes.NewReader(b))
	req2.Header.Set("Content-Type", "application/json")
	res2, err := badClient.Do(req2)
	if err == nil {
		// Handshake succeeded (e.g. optional client auth) — the server must still not serve the request.
		defer res2.Body.Close()
		if res2.StatusCode >= 200 && res2.StatusCode < 300 {
			t.Fatalf("request without client cert succeeded with status %d", res2.StatusCode)
		}
	}
}

func TestMTLSUnknownCertDenied(t *testing.T) {
	bundle, err := tlstest.Generate()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := bootstrap.NewPlatform(bootstrap.Config{})
	// Do NOT register fingerprint

	srv, _ := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{
		TLSConfig:   bundle.ServerTLSConfig(),
		RequireMTLS: true,
	})
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = bundle.ServerTLSConfig()
	ts.StartTLS()
	defer ts.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: bundle.ClientTLSConfig()}}
	body := `{"operation":"document.read","boundary":"dev","input":{"id":"1"},"resource":{"type":"document","id":"1"}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/execute", bytes.NewReader([]byte(body)))
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == 200 {
		t.Fatal("unknown cert must not allow")
	}
}
