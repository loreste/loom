package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

func TestMetricsEndpointIsOptInAndVersioned(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	m := runtime.NewMetrics()
	m.Observe(runtime.Observation{Decision: core.DecisionDeny, Step: "authenticate", Reason: core.ReasonUnauthenticated})
	srv, err := NewServer(p.Runtime, ServerConfig{Metrics: m, MetricsPublic: true})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d", res.Code)
	}
	if res.Header().Get(core.ProtocolHeader) != core.ProtocolVersion {
		t.Fatalf("protocol header = %q", res.Header().Get(core.ProtocolHeader))
	}
	if !strings.Contains(res.Body.String(), "loom_execute_denied_total 1") {
		t.Fatalf("metrics = %s", res.Body.String())
	}
}

func TestMetricsEndpointRequiresExplicitAccess(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{PolicySyncInterval: -1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	srv, err := NewServer(p.Runtime, ServerConfig{Metrics: runtime.NewMetrics()})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}
