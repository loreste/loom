// Package document registers a simple governed read/write document API.
package document

import (
	"fmt"
	"sync"

	"github.com/loreste/loom/core"
)

const (
	OpRead  = "document.read"
	OpWrite = "document.write"
)

// Store is a trivial in-memory document store for demos.
type Store struct {
	mu   sync.RWMutex
	docs map[string]map[string]any
}

// NewStore creates an empty store.
func NewStore() *Store {
	return &Store{docs: make(map[string]map[string]any)}
}

// Register wires operations using the given store.
func Register(reg *core.Registry, store *Store) error {
	if reg == nil || store == nil {
		return fmt.Errorf("%w: registry and store required", core.ErrInvalidArgument)
	}
	readSchema := []byte(`{
		"type":"object",
		"properties":{"id":{"type":"string","minLength":1,"maxLength":128}},
		"required":["id"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:            OpRead,
		Description:     "Read a document",
		InputSchema:     readSchema,
		Permissions:     []string{"document.read"},
		Resources:       []string{"document"},
		Risk:            core.RiskLow,
		Effects:         []core.Effect{core.EffectRead},
		SensitiveFields: []string{"internal_notes"},
	}, store.handleRead); err != nil {
		return err
	}

	writeSchema := []byte(`{
		"type":"object",
		"properties":{
			"id":{"type":"string","minLength":1,"maxLength":128},
			"title":{"type":"string","maxLength":200},
			"body":{"type":"string","maxLength":20000}
		},
		"required":["id","title"],
		"additionalProperties":false
	}`)
	return reg.Register(&core.Operation{
		Name:            OpWrite,
		Description:     "Write a document",
		InputSchema:     writeSchema,
		Permissions:     []string{"document.write"},
		Resources:       []string{"document"},
		Risk:            core.RiskMedium,
		Effects:         []core.Effect{core.EffectWrite},
		Idempotency:     core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
		Quota:           core.QuotaPolicy{Enabled: true},
		SensitiveFields: []string{"internal_notes"},
	}, store.handleWrite)
}

func (s *Store) handleRead(ec *core.ExecutionContext) (*core.Result, error) {
	id, _ := ec.Input["id"].(string)
	s.mu.RLock()
	doc, ok := s.docs[id]
	s.mu.RUnlock()
	if !ok {
		// default demo doc
		return &core.Result{Output: map[string]any{
			"id":             id,
			"title":          "Hello Loom",
			"body":           "Governed read succeeded",
			"internal_notes": "classified",
		}}, nil
	}
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[k] = v
	}
	out["id"] = id
	return &core.Result{Output: out}, nil
}

func (s *Store) handleWrite(ec *core.ExecutionContext) (*core.Result, error) {
	id, _ := ec.Input["id"].(string)
	title, _ := ec.Input["title"].(string)
	body, _ := ec.Input["body"].(string)
	doc := map[string]any{
		"title": title,
		"body":  body,
	}
	s.mu.Lock()
	s.docs[id] = doc
	s.mu.Unlock()
	return &core.Result{Output: map[string]any{
		"id":     id,
		"title":  title,
		"status": "written",
	}}, nil
}
