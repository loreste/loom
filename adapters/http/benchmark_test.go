package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/internal/testtokens"
)

// BenchmarkExecuteHTTP measures the HTTP adapter plus the governed runtime.
// It uses the same in-memory stack as the unit tests and excludes network,
// PostgreSQL, Redis, external identity, and provider latency.
func BenchmarkExecuteHTTP(b *testing.B) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{DemoTokens: testtokens.Demo()})
	if err != nil {
		b.Fatal(err)
	}
	srv, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{Addr: ":0"})
	if err != nil {
		b.Fatal(err)
	}
	body := `{"operation":"document.read","boundary":"dev","input":{"id":"1"},"resource":{"type":"document","id":"1"}}`
	h := srv.Handler()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer alice-secret-token")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("HTTP status = %d", rr.Code)
		}
	}
}
