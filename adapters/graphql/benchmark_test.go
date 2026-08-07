package graphql_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	loomgql "github.com/loreste/loom/adapters/graphql"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/internal/testtokens"
)

// BenchmarkExecuteHTTP measures the GraphQL HTTP adapter plus the governed
// in-memory runtime. It excludes PostgreSQL, Redis, and external providers.
func BenchmarkExecuteHTTP(b *testing.B) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{DemoTokens: testtokens.Demo()})
	if err != nil {
		b.Fatal(err)
	}
	handler, err := loomgql.Handler(p.Runtime)
	if err != nil {
		b.Fatal(err)
	}
	body := `{"query":"mutation { execute(input: { operation: \"document.read\" boundary: \"dev\" input: \"{\\\"id\\\":\\\"1\\\"}\" resource: { type: \"document\" id: \"1\" } }) { allowed } }"}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer alice-secret-token")
		record := httptest.NewRecorder()
		handler.ServeHTTP(record, req)
		if record.Code != http.StatusOK {
			b.Fatalf("GraphQL status = %d", record.Code)
		}
	}
}
