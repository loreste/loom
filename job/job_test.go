package job_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/db"
	"github.com/loreste/loom/domains/orders"
	"github.com/loreste/loom/job"
)

func TestJobRunnerThroughLoom(t *testing.T) {
	a, err := app.New(app.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	sqldb, _ := sql.Open("sqlite", "file:jobtest?mode=memory&cache=shared")
	mig := db.NewMigrator(sqldb, db.DialectSQLite)
	if err := mig.Apply(context.Background(), orders.Migrations()); err != nil {
		t.Fatal(err)
	}
	_ = a.DBs.RegisterDB("main", sqldb, db.Options{
		DriverName: "sqlite", Dialect: db.DialectSQLite, AllowedTables: []string{"orders"},
	})
	_ = orders.Register(a.Registry, orders.Deps{DBs: a.DBs, Pool: "main"})
	_ = a.AddUser("svc:worker", "tok", "dev", []string{"order.create", "order.read"})
	_ = a.GrantOp("svc:worker", "dev", "order.create", "order", "*",
		[]string{"id", "customer", "sku", "qty", "status", "created_at"})

	q := job.NewMemoryQueue()
	_ = q.Enqueue(context.Background(), job.Job{
		ID:        "j1",
		Operation: "order.create",
		Boundary:  "dev",
		Resource:  &core.ResourceRef{Type: "order", ID: "*"},
		Input:     map[string]any{"customer": "c", "sku": "S", "qty": 1},
	})

	r := &job.Runner{Queue: q, Caller: a, Token: "tok"}
	res, ok, err := r.ProcessOne(context.Background())
	if err != nil || !ok {
		t.Fatalf("%v ok=%v", err, ok)
	}
	if !res.Response.Allowed {
		t.Fatalf("%+v", res.Response.Denial)
	}
}

func TestJobDeniedWithoutCaps(t *testing.T) {
	a, _ := app.New(app.Config{})
	t.Cleanup(func() { _ = a.Close() })
	_ = a.AddUser("svc:empty", "tok", "dev", []string{}) // no caps
	q := job.NewMemoryQueue()
	_ = q.Enqueue(context.Background(), job.Job{
		ID: "x", Operation: "order.create", Boundary: "dev",
		Input: map[string]any{"customer": "c", "sku": "S", "qty": 1},
	})
	r := &job.Runner{Queue: q, Caller: a, Token: "tok"}
	res, ok, _ := r.ProcessOne(context.Background())
	if !ok || res.Response.Allowed {
		t.Fatal("must deny")
	}
	// A real policy denial is not an infra error.
	if res.Err != nil {
		t.Fatalf("policy denial must not populate Err: %v", res.Err)
	}
}

// stubCaller captures the request and returns a canned response.
type stubCaller struct {
	req  core.Request
	resp core.Response
}

func (s *stubCaller) Call(_ context.Context, req core.Request) core.Response {
	s.req = req
	return s.resp
}

// TestJobMetadataCannotOverrideJobID: adapter baggage must not clobber the
// runner-owned job_id / adapter audit metadata.
func TestJobMetadataCannotOverrideJobID(t *testing.T) {
	sc := &stubCaller{resp: core.Response{Allowed: true, Decision: core.DecisionAllow}}
	q := job.NewMemoryQueue()
	_ = q.Enqueue(context.Background(), job.Job{
		ID: "real-job", Operation: "op", Boundary: "dev",
		Metadata: map[string]string{"job_id": "forged", "adapter": "forged", "user_agent": "x"},
	})
	r := &job.Runner{Queue: q, Caller: sc, Token: "tok"}
	if _, ok, err := r.ProcessOne(context.Background()); err != nil || !ok {
		t.Fatalf("%v ok=%v", err, ok)
	}
	if got := sc.req.Metadata["job_id"]; got != "real-job" {
		t.Fatalf("job_id = %q, want real-job", got)
	}
	if got := sc.req.Metadata["adapter"]; got != "job" {
		t.Fatalf("adapter = %q, want job", got)
	}
	if got := sc.req.Metadata["user_agent"]; got != "x" {
		t.Fatalf("user_agent = %q, want x", got)
	}
}

// TestJobResultErrInfraVsDeny: internal-class failures populate Err; policy
// denials do not.
func TestJobResultErrInfraVsDeny(t *testing.T) {
	sc := &stubCaller{resp: core.Response{
		Allowed: false,
		Denial:  core.NewDenial("handler", core.ReasonInternal, "internal error", nil),
	}}
	q := job.NewMemoryQueue()
	_ = q.Enqueue(context.Background(), job.Job{ID: "j1", Operation: "op", Boundary: "dev"})
	r := &job.Runner{Queue: q, Caller: sc, Token: "tok"}
	res, ok, err := r.ProcessOne(context.Background())
	if err != nil || !ok {
		t.Fatalf("%v ok=%v", err, ok)
	}
	if res.Err == nil {
		t.Fatal("infra-class failure must populate Result.Err")
	}

	sc.resp = core.Response{
		Allowed: false,
		Denial:  core.NewDenial("policy", core.ReasonPolicyDeny, "denied by policy", nil),
	}
	_ = q.Enqueue(context.Background(), job.Job{ID: "j2", Operation: "op", Boundary: "dev"})
	res, ok, err = r.ProcessOne(context.Background())
	if err != nil || !ok {
		t.Fatalf("%v ok=%v", err, ok)
	}
	if res.Err != nil {
		t.Fatalf("policy denial must leave Err nil, got %v", res.Err)
	}
}
