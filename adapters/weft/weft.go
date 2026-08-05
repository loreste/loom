// Package weft adapts Weft workflow/step invocations into Loom.
// Core does not import this package. Weft cannot bypass Runtime.Execute.
//
// Weft is treated as an untrusted caller surface: credentials, boundary, and
// operation are always re-validated by the runtime pipeline.
package weft

import (
	"context"
	"fmt"
	"strings"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

// StepCall is a Weft-shaped workflow step invocation.
type StepCall struct {
	// WorkflowID correlates multi-step runs (audit metadata only).
	WorkflowID string
	// StepID is the step name within the workflow (metadata).
	StepID string
	// Operation is the Loom operation to execute (required).
	Operation        string
	OperationVersion string
	// BearerToken / credentials for authentication.
	BearerToken string
	// Scheme defaults to bearer; use "mtls" only when adapter injects verified cert material.
	Scheme string
	// Boundary isolation target.
	Boundary string
	// Input step payload.
	Input map[string]any
	// Resource optional subject.
	Resource *core.ResourceRef
	// Fields output projection.
	Fields []string
	// IdempotencyKey recommended for write/money steps.
	IdempotencyKey string
	// ApprovalToken when prior human approval is required.
	ApprovalToken string
	// Delegation optional chain.
	Delegation *core.DelegationChain
	// Metadata extra Weft baggage (never authoritative for allow).
	Metadata map[string]string
}

// Adapter translates Weft calls into Loom requests.
type Adapter struct {
	RT *runtime.Runtime
	// AllowedOperations if non-empty, rejects ops not in the set before runtime
	// (defense in depth; runtime still enforces policy).
	AllowedOperations map[string]struct{}
	// NamePrefix stripped from Operation when present (e.g. "weft.").
	NamePrefix string
}

// New creates a Weft adapter.
func New(rt *runtime.Runtime) *Adapter {
	return &Adapter{RT: rt}
}

// Invoke runs a workflow step under full governance.
func (a *Adapter) Invoke(ctx context.Context, call StepCall) (core.Response, error) {
	if a == nil || a.RT == nil {
		return core.Response{}, fmt.Errorf("weft: runtime not configured")
	}
	op := strings.TrimSpace(call.Operation)
	if a.NamePrefix != "" && strings.HasPrefix(op, a.NamePrefix) {
		op = strings.TrimPrefix(op, a.NamePrefix)
	}
	if op == "" {
		return core.Response{
			Allowed:  false,
			Decision: core.DecisionDeny,
			Denial:   core.NewDenial("weft", core.ReasonOperationUnknown, "operation required", nil),
		}, nil
	}
	if a.AllowedOperations != nil {
		if _, ok := a.AllowedOperations[op]; !ok {
			return core.Response{
				Allowed:  false,
				Decision: core.DecisionDeny,
				Denial:   core.NewDenial("weft", core.ReasonOperationDenied, "operation not allowed by weft adapter allowlist", nil),
			}, nil
		}
	}

	scheme := call.Scheme
	if scheme == "" {
		scheme = "bearer"
	}
	md := map[string]string{
		"adapter":     "weft",
		"workflow_id": call.WorkflowID,
		"step_id":     call.StepID,
	}
	for k, v := range call.Metadata {
		// Do not let caller overwrite adapter identity
		if k == "adapter" {
			continue
		}
		if k == "x-loom-bypass" || k == "x-admin-override" {
			md[k] = v // recorded; policy hard-denies
			continue
		}
		md[k] = v
	}

	req := core.Request{
		Operation:        op,
		OperationVersion: call.OperationVersion,
		Credentials: core.Credentials{
			Scheme: scheme,
			Token:  call.BearerToken,
		},
		Delegation:     call.Delegation,
		Boundary:       core.BoundaryID(call.Boundary),
		Resource:       call.Resource,
		Input:          call.Input,
		Fields:         call.Fields,
		IdempotencyKey: call.IdempotencyKey,
		ApprovalToken:  call.ApprovalToken,
		Metadata:       md,
	}
	return a.RT.Execute(ctx, req), nil
}

// BatchInvoke runs steps sequentially. Stops on first deny if StopOnDeny.
// There is no privilege inheritance between steps.
type BatchResult struct {
	Responses []core.Response
	Stopped   bool
}

// BatchOptions configures batch execution.
type BatchOptions struct {
	StopOnDeny bool
}

// BatchInvoke executes multiple steps.
func (a *Adapter) BatchInvoke(ctx context.Context, calls []StepCall, opt BatchOptions) (BatchResult, error) {
	var out BatchResult
	for _, c := range calls {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		resp, err := a.Invoke(ctx, c)
		if err != nil {
			return out, err
		}
		out.Responses = append(out.Responses, resp)
		if opt.StopOnDeny && !resp.Allowed {
			out.Stopped = true
			break
		}
	}
	return out, nil
}
