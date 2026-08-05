package resource_test

import (
	"sync"
	"testing"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/resource"
)

// TestFieldFilterConcurrentGrantAndFilter hammers GrantFields (writer) and
// Filter (reader) on the same key. Run with -race: before the fix, Filter
// read the inner grant map after releasing RLock → concurrent map access.
func TestFieldFilterConcurrentGrantAndFilter(t *testing.T) {
	f := resource.NewFieldFilter()
	id := core.Identity{ID: "user:alice"}
	out := map[string]any{"id": "1", "title": "t", "secret": "s"}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if err := f.GrantFields("user:alice", "dev", "document.read", []string{"id", "title"}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				got, err := f.Filter(id, "dev", "document.read", nil, []string{"secret"}, out)
				if err != nil {
					t.Error(err)
					return
				}
				if _, ok := got["secret"]; ok {
					t.Error("sensitive field leaked without explicit grant")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestInputFieldsAreSeparateFromOutputFields(t *testing.T) {
	f := resource.NewFieldFilter()
	if err := f.GrantFields("user:alice", "dev", "customer.update", []string{"id", "name"}); err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeInput(core.Identity{ID: "user:alice"}, "dev", "customer.update", nil, map[string]any{"name": "A"}); err == nil {
		t.Fatal("output grant must not authorize input")
	}
	if err := f.GrantInputFields("user:alice", "dev", "customer.update", []string{"name"}); err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeInput(core.Identity{ID: "user:alice"}, "dev", "customer.update", nil, map[string]any{"role": "admin"}); err == nil {
		t.Fatal("unlisted input field must be denied")
	}
}
