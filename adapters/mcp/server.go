// Package mcp: JSON-RPC 2.0 wire server for MCP tools/* over any byte stream.
//
// This speaks a minimal subset of the Model Context Protocol so agents
// (Claude Desktop, Cursor, custom clients) can list and call Loom operations
// without a bespoke REST API. Every tools/call goes through Adapter.Call →
// Runtime.Execute. There is no privileged path.
//
// Auth: bearer token from:
//  1. JSON-RPC params._meta.authorization / params.bearer_token (tools/call)
//  2. Server.Token (stdio / process env LOOM_TOKEN)
//
// Tokens in JSON-RPC params are accepted for stdio transports that cannot set
// HTTP headers; prefer Server.Token for long-lived processes.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/loreste/loom/catalog"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
)

const (
	jsonrpcVersion     = "2.0"
	defaultMaxMsgBytes = 1 << 20 // 1 MiB
	protocolVersion    = "2024-11-05"
)

// Server is a minimal MCP JSON-RPC endpoint backed by a Loom adapter.
type Server struct {
	Adapter *Adapter
	// Registry used for tools/list specs (filtered by authenticated capabilities).
	Registry *core.Registry
	// Verifier authenticates bearer tokens for tools/list filtering.
	// If nil, tools/list returns an empty list (fail closed).
	Verifier identity.Verifier
	// Token default bearer (e.g. from LOOM_TOKEN). Used when the call omits one.
	Token string
	// tokenLocked means Token came from the transport (HTTP Authorization) and
	// must not be overridden by JSON-RPC body bearer fields.
	tokenLocked bool
	// Boundary default boundary when the call omits one.
	Boundary string
	// MaxMessageBytes caps a single JSON-RPC frame (default 1 MiB).
	MaxMessageBytes int
	// ServerInfo reported on initialize.
	ServerName    string
	ServerVersion string
}

// jsonrpcReq is a JSON-RPC 2.0 request.
type jsonrpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonrpcResp is a JSON-RPC 2.0 response.
type jsonrpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
)

// Handle processes one JSON-RPC message and returns the response bytes.
// Notifications (no id) return nil, nil.
// Oversized or malformed input yields a JSON-RPC error response when possible.
func (s *Server) Handle(ctx context.Context, raw []byte) ([]byte, error) {
	if s == nil || s.Adapter == nil || s.Adapter.RT == nil {
		return marshalResp(nil, nil, &rpcError{Code: rpcInternalError, Message: "mcp server not configured"})
	}
	max := s.MaxMessageBytes
	if max <= 0 {
		max = defaultMaxMsgBytes
	}
	if len(raw) > max {
		return marshalResp(nil, nil, &rpcError{Code: rpcInvalidRequest, Message: "message too large"})
	}
	var req jsonrpcReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return marshalResp(nil, nil, &rpcError{Code: rpcParseError, Message: "parse error"})
	}
	if req.JSONRPC != "" && req.JSONRPC != jsonrpcVersion {
		return marshalResp(req.ID, nil, &rpcError{Code: rpcInvalidRequest, Message: "unsupported jsonrpc version"})
	}
	// Notifications: no id → no response.
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	if strings.HasPrefix(req.Method, "notifications/") {
		return nil, nil
	}

	result, rpcErr := s.dispatch(ctx, req)
	if isNotification {
		return nil, nil
	}
	return marshalResp(req.ID, result, rpcErr)
}

func (s *Server) dispatch(ctx context.Context, req jsonrpcReq) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req.Params)
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return s.handleToolsList(ctx, req.Params)
	case "tools/call":
		return s.handleToolsCall(ctx, req.Params)
	default:
		return nil, &rpcError{Code: rpcMethodNotFound, Message: "method not found: " + req.Method}
	}
}

func (s *Server) handleInitialize(params json.RawMessage) (any, *rpcError) {
	name := s.ServerName
	if name == "" {
		name = "loom"
	}
	ver := s.ServerVersion
	if ver == "" {
		ver = "1"
	}
	_ = params // client info ignored; no privilege
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    name,
			"version": ver,
		},
	}, nil
}

type toolsListParams struct {
	// Optional bearer for capability-filtered listing.
	BearerToken string `json:"bearer_token,omitempty"`
	Meta        struct {
		Authorization string `json:"authorization,omitempty"`
	} `json:"_meta,omitempty"`
}

func (s *Server) handleToolsList(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var bodyTok, metaAuth string
	if len(params) > 0 {
		var p toolsListParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{Code: rpcInvalidParams, Message: "invalid params"}
		}
		bodyTok, metaAuth = p.BearerToken, p.Meta.Authorization
	}
	token := s.resolveToken(bodyTok, metaAuth)
	// Fail closed: no token or no verifier → empty tool list (no schema leak).
	if token == "" || s.Verifier == nil || s.Registry == nil {
		return map[string]any{"tools": []any{}}, nil
	}
	id, err := s.Verifier.Authenticate(ctx, core.Credentials{Scheme: "bearer", Token: token})
	if err != nil {
		// Unknown token: empty list (do not leak whether ops exist).
		return map[string]any{"tools": []any{}}, nil
	}
	specs := catalog.Build(s.Registry, catalog.ForCapabilities(id.Capabilities))
	tools := make([]map[string]any, 0, len(specs))
	for _, sp := range specs {
		tool := map[string]any{
			"name":        sp.Name,
			"description": sp.Description,
		}
		if len(sp.InputSchema) > 0 {
			var schema any
			if err := json.Unmarshal(sp.InputSchema, &schema); err == nil {
				tool["inputSchema"] = schema
			}
		} else {
			tool["inputSchema"] = map[string]any{"type": "object"}
		}
		tools = append(tools, tool)
	}
	return map[string]any{"tools": tools}, nil
}

type toolsCallParams struct {
	Name             string         `json:"name"`
	OperationVersion string         `json:"operation_version,omitempty"`
	Arguments        map[string]any `json:"arguments"`
	// Loom extensions (optional).
	BearerToken    string            `json:"bearer_token,omitempty"`
	Boundary       string            `json:"boundary,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
	ApprovalToken  string            `json:"approval_token,omitempty"`
	Resource       *core.ResourceRef `json:"resource,omitempty"`
	Meta           struct {
		Authorization string `json:"authorization,omitempty"`
	} `json:"_meta,omitempty"`
}

// HandleWithToken is Handle with a per-request bearer from the transport
// (HTTP Authorization). When token is non-empty it wins over JSON-RPC body
// bearer fields (fail closed against proxy/WAF confusion).
func (s *Server) HandleWithToken(ctx context.Context, raw []byte, token string) ([]byte, error) {
	if s == nil {
		return marshalResp(nil, nil, &rpcError{Code: rpcInternalError, Message: "mcp server not configured"})
	}
	if token == "" {
		return s.Handle(ctx, raw)
	}
	// Shallow copy so concurrent HTTP requests do not race on Server.Token.
	cp := *s
	cp.Token = token
	cp.tokenLocked = true
	return cp.Handle(ctx, raw)
}

func (s *Server) resolveToken(bodyToken, metaAuth string) string {
	// Transport-locked token always wins.
	if s != nil && s.tokenLocked && s.Token != "" {
		return s.Token
	}
	if t := bearerFrom(bodyToken, metaAuth); t != "" {
		return t
	}
	if s != nil {
		return s.Token
	}
	return ""
}

func (s *Server) handleToolsCall(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	if len(params) == 0 {
		return nil, &rpcError{Code: rpcInvalidParams, Message: "params required"}
	}
	var p toolsCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: rpcInvalidParams, Message: "invalid params"}
	}
	if p.Name == "" {
		return nil, &rpcError{Code: rpcInvalidParams, Message: "name required"}
	}
	token := s.resolveToken(p.BearerToken, p.Meta.Authorization)
	boundary := p.Boundary
	if boundary == "" {
		boundary = s.Boundary
	}
	resp, err := s.Adapter.Call(ctx, ToolCall{
		Name:             p.Name,
		OperationVersion: p.OperationVersion,
		Arguments:        p.Arguments,
		BearerToken:      token,
		Boundary:         boundary,
		IdempotencyKey:   p.IdempotencyKey,
		ApprovalToken:    p.ApprovalToken,
		Resource:         p.Resource,
	})
	if err != nil {
		return nil, &rpcError{Code: rpcInternalError, Message: "call failed"}
	}
	// MCP tools/call result shape: content[] + isError.
	if !resp.Allowed {
		msg := "denied"
		if resp.Denial != nil {
			// Only static reason/message — no internal leak (runtime already sanitized).
			msg = resp.Denial.Reason
			if resp.Denial.Hint != "" {
				msg = msg + ": " + resp.Denial.Hint
			}
		}
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": msg}},
			"isError": true,
			// Loom extension for machine-readable denials.
			"_loom": map[string]any{
				"allowed":   false,
				"reason":    denialReason(resp),
				"hint":      denialHint(resp),
				"retryable": denialRetryable(resp),
				"trace_id":  resp.TraceID,
			},
		}, nil
	}
	out, _ := json.Marshal(resp.Output)
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(out)}},
		"isError": false,
		"_loom": map[string]any{
			"allowed":  true,
			"trace_id": resp.TraceID,
			"audit_id": resp.AuditID,
			"output":   resp.Output,
		},
	}, nil
}

func denialReason(r core.Response) string {
	if r.Denial == nil {
		return ""
	}
	return r.Denial.Reason
}
func denialHint(r core.Response) string {
	if r.Denial == nil {
		return ""
	}
	return r.Denial.Hint
}
func denialRetryable(r core.Response) bool {
	if r.Denial == nil {
		return false
	}
	return r.Denial.Retryable
}

func bearerFrom(token, authHeader string) string {
	if token != "" {
		return token
	}
	h := strings.TrimSpace(authHeader)
	if h == "" {
		return ""
	}
	const p = "bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return h
}

func marshalResp(id json.RawMessage, result any, err *rpcError) ([]byte, error) {
	resp := jsonrpcResp{JSONRPC: jsonrpcVersion, ID: id}
	if err != nil {
		resp.Error = err
	} else {
		resp.Result = result
	}
	return json.Marshal(resp)
}

// ServeStream reads newline-delimited JSON-RPC from in and writes responses to out.
// Each message is one JSON object followed by '\n' (MCP stdio framing lite).
// Exits when in is exhausted or ctx is cancelled.
func (s *Server) ServeStream(ctx context.Context, in io.Reader, out io.Writer) error {
	if s == nil {
		return fmt.Errorf("mcp: nil server")
	}
	max := s.MaxMessageBytes
	if max <= 0 {
		max = defaultMaxMsgBytes
	}
	sc := bufio.NewScanner(in)
	// Allow large but bounded lines.
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, max)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := sc.Bytes()
		if len(bytesTrimSpace(line)) == 0 {
			continue
		}
		resp, err := s.Handle(ctx, line)
		if err != nil {
			return err
		}
		if resp == nil {
			continue // notification
		}
		if _, err := out.Write(resp); err != nil {
			return err
		}
		if _, err := out.Write([]byte("\n")); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		// Scanner errors on oversize lines — map to a clean exit.
		return fmt.Errorf("mcp: read: %w", err)
	}
	return nil
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
