// Package grpc adapts gRPC to Loom. It never bypasses the runtime.
//
// Auth: gRPC metadata key "authorization" with value "Bearer <token>".
// Hostile metadata (x-loom-bypass, x-admin-override) is recorded for policy
// tripwires and never grants privilege.
package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	loomv1 "github.com/loreste/loom/adapters/grpc/gen/loom/v1"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

// Server implements loom.v1.RuntimeServer.
type Server struct {
	loomv1.UnimplementedRuntimeServer
	RT *runtime.Runtime
}

// NewServer wraps a Loom runtime. RT required.
func NewServer(rt *runtime.Runtime) (*Server, error) {
	if rt == nil {
		return nil, fmt.Errorf("%w: runtime required", core.ErrInvalidArgument)
	}
	return &Server{RT: rt}, nil
}

// Register attaches the Runtime service to a gRPC server.
func Register(gs *grpc.Server, rt *runtime.Runtime) error {
	s, err := NewServer(rt)
	if err != nil {
		return err
	}
	loomv1.RegisterRuntimeServer(gs, s)
	return nil
}

// Execute maps a gRPC call onto Runtime.Execute — the only entrypoint.
func (s *Server) Execute(ctx context.Context, req *loomv1.ExecuteRequest) (*loomv1.ExecuteResponse, error) {
	if s == nil || s.RT == nil {
		return nil, status.Error(codes.FailedPrecondition, "runtime not configured")
	}
	if req == nil || req.Operation == "" {
		return nil, status.Error(codes.InvalidArgument, "operation required")
	}

	token, md := extractAuthAndMeta(ctx, req.Metadata)
	input, err := decodeInputJSON(req.InputJson)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid input_json")
	}

	coreReq := core.Request{
		Operation: req.Operation,
		Credentials: core.Credentials{
			Scheme: "bearer",
			Token:  token,
		},
		Boundary:       core.BoundaryID(req.Boundary),
		Input:          input,
		Fields:         append([]string(nil), req.Fields...),
		IdempotencyKey: req.IdempotencyKey,
		ApprovalToken:  req.ApprovalToken,
		Metadata:       md,
		TraceID:        req.TraceId,
	}
	if req.ResourceType != "" || req.ResourceId != "" {
		coreReq.Resource = &core.ResourceRef{
			Type: req.ResourceType,
			ID:   req.ResourceId,
		}
	}

	resp := s.RT.Execute(ctx, coreReq)
	return toProto(resp), nil
}

func extractAuthAndMeta(ctx context.Context, clientMD map[string]string) (token string, md map[string]string) {
	md = map[string]string{"adapter": "grpc"}
	// Client-supplied metadata first (untrusted baggage only).
	for k, v := range clientMD {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" || lk == "authorization" || lk == "adapter" {
			continue
		}
		// Cap value size to limit abuse.
		if len(v) > 512 {
			v = v[:512]
		}
		md[lk] = v
	}
	if grpcMD, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := grpcMD.Get("authorization"); len(vals) > 0 {
			token = bearer(vals[0])
		}
		// Record hostile headers for policy tripwires (never as grants).
		for _, key := range []string{"x-loom-bypass", "x-admin-override"} {
			if vals := grpcMD.Get(key); len(vals) > 0 && vals[0] != "" {
				md[key] = "1"
			}
		}
		if vals := grpcMD.Get("x-trace-id"); len(vals) > 0 && vals[0] != "" {
			// Prefer request field; only fill if empty later.
			if md["x-trace-id"] == "" {
				md["x-trace-id"] = vals[0]
			}
		}
	}
	return token, md
}

func bearer(h string) string {
	const p = "Bearer "
	h = strings.TrimSpace(h)
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	// Also accept raw token (some clients omit scheme).
	if h != "" && !strings.Contains(h, " ") {
		return h
	}
	return ""
}

func decodeInputJSON(s string) (map[string]any, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func toProto(resp core.Response) *loomv1.ExecuteResponse {
	out := &loomv1.ExecuteResponse{
		Allowed:          resp.Allowed,
		Decision:         resp.Decision.String(),
		TraceId:          resp.TraceID,
		AuditId:          resp.AuditID,
		IdempotentReplay: resp.IdempotentReplay,
		Risk:             resp.Risk.String(),
	}
	if resp.Output != nil {
		b, err := json.Marshal(resp.Output)
		if err == nil {
			out.OutputJson = string(b)
		}
	}
	if resp.Denial != nil {
		out.DenialReason = resp.Denial.Reason
		out.DenialMessage = resp.Denial.Message
		out.DenialStep = resp.Denial.Step
		out.DenialRetryable = resp.Denial.Retryable
		out.DenialHint = resp.Denial.Hint
	}
	return out
}
