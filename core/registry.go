package core

import (
	"fmt"
	"sync"
)

// Handler executes business logic after the full enforcement pipeline has passed.
// Handlers must assume input is schema-validated but still treat data as hostile.
type Handler func(ec *ExecutionContext) (*Result, error)

// Registry maps operation names to definitions and handlers.
// Unknown operations are denied. Registration is explicit.
type Registry struct {
	mu       sync.RWMutex
	ops      map[string]*Operation
	handlers map[string]Handler
}

// NewRegistry returns an empty registry (deny everything until registered).
func NewRegistry() *Registry {
	return &Registry{
		ops:      make(map[string]*Operation),
		handlers: make(map[string]Handler),
	}
}

// Register adds an operation and its handler.
// Overwriting an existing name returns ErrAlreadyExists (fail closed on ambiguity).
func (r *Registry) Register(op *Operation, h Handler) error {
	if r == nil {
		return fmt.Errorf("%w: nil registry", ErrInvalidArgument)
	}
	if op == nil || op.Name == "" {
		return fmt.Errorf("%w: operation name required", ErrInvalidArgument)
	}
	if h == nil {
		return fmt.Errorf("%w: handler required", ErrInvalidArgument)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.ops[op.Name]; exists {
		return fmt.Errorf("%w: operation %q", ErrAlreadyExists, op.Name)
	}
	// Copy to prevent external mutation after register.
	registered := copyOperation(op)
	registered.Version = NormalizeOperationVersion(registered.Version)
	r.ops[op.Name] = registered
	r.handlers[op.Name] = h
	return nil
}

// copyOperation deep-copies an Operation so callers can never alias (and
// mutate) the registry's internal definition.
func copyOperation(op *Operation) *Operation {
	cp := *op
	if op.Permissions != nil {
		cp.Permissions = append([]string(nil), op.Permissions...)
	}
	if op.Resources != nil {
		cp.Resources = append([]string(nil), op.Resources...)
	}
	if op.Effects != nil {
		cp.Effects = append([]Effect(nil), op.Effects...)
	}
	if op.SensitiveFields != nil {
		cp.SensitiveFields = append([]string(nil), op.SensitiveFields...)
	}
	if op.Limits != nil {
		cp.Limits = make(map[string]int64, len(op.Limits))
		for k, v := range op.Limits {
			cp.Limits[k] = v
		}
	}
	if op.Approval.Effects != nil {
		cp.Approval.Effects = append([]Effect(nil), op.Approval.Effects...)
	}
	return &cp
}

// MustRegister panics on error. Use only in package init / main wiring.
func (r *Registry) MustRegister(op *Operation, h Handler) {
	if err := r.Register(op, h); err != nil {
		panic(err)
	}
}

// Get returns a deep copy of the operation definition or ErrNotFound.
// The copy is deliberate: a holder must not be able to mutate permissions /
// risk / approval policy concurrently with Execute reading them.
func (r *Registry) Get(name string) (*Operation, error) {
	if r == nil {
		return nil, ErrNotFound
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	op, ok := r.ops[name]
	if !ok {
		return nil, fmt.Errorf("%w: operation %q", ErrNotFound, name)
	}
	return copyOperation(op), nil
}

// GetVersion returns an operation only when the requested contract version
// matches exactly. Empty version means DefaultOperationVersion.
func (r *Registry) GetVersion(name, version string) (*Operation, error) {
	op, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	if NormalizeOperationVersion(version) != NormalizeOperationVersion(op.Version) {
		return nil, fmt.Errorf("%w: operation %q version %q", ErrNotFound, name, version)
	}
	return op, nil
}

// Handler returns the handler or ErrNotFound.
func (r *Registry) Handler(name string) (Handler, error) {
	if r == nil {
		return nil, ErrNotFound
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[name]
	if !ok {
		return nil, fmt.Errorf("%w: handler %q", ErrNotFound, name)
	}
	return h, nil
}

// Names returns registered operation names (snapshot).
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.ops))
	for n := range r.ops {
		out = append(out, n)
	}
	return out
}
