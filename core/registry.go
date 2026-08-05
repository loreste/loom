package core

import (
	"fmt"
	"sort"
	"sync"
)

// Handler executes business logic after the full enforcement pipeline has passed.
type Handler func(ec *ExecutionContext) (*Result, error)

// Registry maps operation names and exact versions to definitions and handlers.
// Unknown operations or versions are denied. Registration is explicit.
type Registry struct {
	mu       sync.RWMutex
	ops      map[string]map[string]*Operation
	handlers map[string]map[string]Handler
}

// NewRegistry returns an empty registry (deny everything until registered).
func NewRegistry() *Registry {
	return &Registry{
		ops:      make(map[string]map[string]*Operation),
		handlers: make(map[string]map[string]Handler),
	}
}

// Register adds an operation and its handler. The same name may have multiple
// exact versions, but registering one version twice is always an error.
func (r *Registry) Register(op *Operation, h Handler) error {
	if r == nil {
		return fmt.Errorf("%w: nil registry", ErrInvalidArgument)
	}
	if op == nil {
		return fmt.Errorf("%w: nil operation", ErrInvalidArgument)
	}
	if op.Name == "" {
		return fmt.Errorf("%w: operation name required", ErrInvalidArgument)
	}
	if h == nil {
		return fmt.Errorf("%w: handler required", ErrInvalidArgument)
	}
	registered := copyOperation(op)
	registered.Version = NormalizeOperationVersion(registered.Version)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ops[registered.Name] == nil {
		r.ops[registered.Name] = make(map[string]*Operation)
		r.handlers[registered.Name] = make(map[string]Handler)
	}
	if _, exists := r.ops[registered.Name][registered.Version]; exists {
		return fmt.Errorf("%w: operation %q version %q", ErrAlreadyExists, registered.Name, registered.Version)
	}
	r.ops[registered.Name][registered.Version] = registered
	r.handlers[registered.Name][registered.Version] = h
	return nil
}

// copyOperation deep-copies an Operation so callers cannot alias and mutate
// the registry's internal definition.
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
	if op.AllowedCurrencies != nil {
		cp.AllowedCurrencies = append([]string(nil), op.AllowedCurrencies...)
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

// Get returns the default version of an operation or ErrNotFound.
func (r *Registry) Get(name string) (*Operation, error) {
	return r.GetVersion(name, DefaultOperationVersion)
}

// GetVersion returns an operation only when the requested contract version
// matches exactly. Empty version means DefaultOperationVersion. No fallback to
// another version is performed.
func (r *Registry) GetVersion(name, version string) (*Operation, error) {
	if r == nil {
		return nil, ErrNotFound
	}
	version = NormalizeOperationVersion(version)
	r.mu.RLock()
	defer r.mu.RUnlock()
	versions, ok := r.ops[name]
	if !ok {
		return nil, ErrNotFound
	}
	op, ok := versions[version]
	if !ok {
		return nil, fmt.Errorf("%w: operation %q version %q", ErrNotFound, name, version)
	}
	return copyOperation(op), nil
}

// Handler returns the default-version handler or ErrNotFound.
func (r *Registry) Handler(name string) (Handler, error) {
	return r.HandlerVersion(name, DefaultOperationVersion)
}

// HandlerVersion returns only the handler bound to the exact version.
func (r *Registry) HandlerVersion(name, version string) (Handler, error) {
	if r == nil {
		return nil, ErrNotFound
	}
	version = NormalizeOperationVersion(version)
	r.mu.RLock()
	defer r.mu.RUnlock()
	versions, ok := r.handlers[name]
	if !ok {
		return nil, fmt.Errorf("%w: handler %q", ErrNotFound, name)
	}
	h, ok := versions[version]
	if !ok {
		return nil, fmt.Errorf("%w: handler %q version %q", ErrNotFound, name, version)
	}
	return h, nil
}

// Names returns registered operation names, without duplicate version entries.
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]string, 0, len(r.ops))
	for name := range r.ops {
		out = append(out, name)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}
