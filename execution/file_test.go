package execution

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/loreste/loom/core"
)

func testUnconfirmedRecord(id string) Record {
	return Record{
		ExecutionID:      id,
		Operation:        "payment.capture",
		OperationVersion: "1",
		Outcome:          core.OutcomeExecutedUnconfirmed,
		State:            StateExecutedUnconfirmed,
		Response: core.Response{
			Outcome:     core.OutcomeExecutedUnconfirmed,
			ExecutionID: id,
			Denial:      &core.Denial{Details: map[string]string{"safe": "original"}},
			Output: map[string]any{
				"nested": map[string]any{"status": "pending"},
				"items":  []any{map[string]any{"value": "original"}},
			},
		},
	}
}

func TestFileStoreReconcilePersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "execution.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), testUnconfirmedRecord("file-reconcile")); err != nil {
		t.Fatal(err)
	}

	got, err := store.Reconcile(context.Background(), "file-reconcile", core.OutcomeAllowed, "processor confirmed")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateReconciled || got.Outcome != core.OutcomeAllowed || !got.Response.Allowed {
		t.Fatalf("unexpected reconciliation: %+v", got)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, ok, err := reopened.Get(context.Background(), "file-reconcile")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || persisted.State != StateReconciled || persisted.Outcome != core.OutcomeAllowed || !persisted.Response.Allowed {
		t.Fatalf("reconciliation was not persisted: %+v, found=%v", persisted, ok)
	}
}

func TestFileStoreRecoveryQueuePersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "execution.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), testUnconfirmedRecord("file-recovery")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRecoveryQueued(context.Background(), "file-recovery"); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, ok, err := reopened.Get(context.Background(), "file-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !persisted.RecoveryQueued {
		t.Fatalf("recovery queue marker was not persisted: %+v, found=%v", persisted, ok)
	}
}

func TestFileStoreConcurrentReconciliationIsIdempotent(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), testUnconfirmedRecord("file-concurrent")); err != nil {
		t.Fatal(err)
	}

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.Reconcile(context.Background(), "file-concurrent", core.OutcomeAllowed, "confirmed")
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	got, ok, err := store.Get(context.Background(), "file-concurrent")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.State != StateReconciled || got.Outcome != core.OutcomeAllowed {
		t.Fatalf("unexpected concurrent result: %+v, found=%v", got, ok)
	}
}

func TestFileStoreFailedWriteKeepsPreviousState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "execution.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), testUnconfirmedRecord("file-failed-write")); err != nil {
		t.Fatal(err)
	}

	// Point persistence at an existing directory. The atomic rename must fail,
	// and the store must roll its in-memory mutation back as well.
	store.path = filepath.Dir(path)
	if _, err := store.Reconcile(context.Background(), "file-failed-write", core.OutcomeAllowed, "should not persist"); err == nil {
		t.Fatal("expected persistence failure")
	}
	current, ok, err := store.Get(context.Background(), "file-failed-write")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.State != StateExecutedUnconfirmed || current.Outcome != core.OutcomeExecutedUnconfirmed {
		t.Fatalf("in-memory state changed after failed write: %+v, found=%v", current, ok)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, ok, err := reopened.Get(context.Background(), "file-failed-write")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || persisted.State != StateExecutedUnconfirmed {
		t.Fatalf("disk state changed after failed write: %+v, found=%v", persisted, ok)
	}
}

func TestExecutionStoresDeepCopyRecords(t *testing.T) {
	stores := []Store{
		NewMemoryStore(),
	}
	fileStore, err := NewFileStore(filepath.Join(t.TempDir(), "execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	stores = append(stores, fileStore)

	for _, store := range stores {
		record := testUnconfirmedRecord("copy")
		if err := store.Put(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		record.Response.Output["nested"].(map[string]any)["status"] = "caller-mutated"
		record.Response.Output["items"].([]any)[0].(map[string]any)["value"] = "caller-mutated"
		record.Response.Denial.Details["safe"] = "caller-mutated"

		got, ok, err := store.Get(context.Background(), "copy")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || got.Response.Output["nested"].(map[string]any)["status"] != "pending" {
			t.Fatalf("Put retained caller aliases: %+v", got.Response.Output)
		}
		if got.Response.Denial.Details["safe"] != "original" {
			t.Fatalf("Put retained denial aliases: %+v", got.Response.Denial.Details)
		}
		got.Response.Output["nested"].(map[string]any)["status"] = "get-mutated"
		got.Response.Denial.Details["safe"] = "get-mutated"

		again, ok, err := store.Get(context.Background(), "copy")
		if err != nil {
			t.Fatal(err)
		}
		if !ok || again.Response.Output["nested"].(map[string]any)["status"] != "pending" {
			t.Fatalf("Get returned stored aliases: %+v", again.Response.Output)
		}
		if again.Response.Denial.Details["safe"] != "original" {
			t.Fatalf("Get returned denial aliases: %+v", again.Response.Denial.Details)
		}
	}
}
