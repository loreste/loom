// Package loom is the Go SDK. Local or remote — never bypasses governance.
package loom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

// Client calls a local Runtime (in-process).
type Client struct {
	RT *runtime.Runtime
}

// NewClient wraps a runtime.
func NewClient(rt *runtime.Runtime) *Client {
	return &Client{RT: rt}
}

// Call invokes an operation under full governance.
func (c *Client) Call(ctx context.Context, req core.Request) core.Response {
	if c == nil || c.RT == nil {
		return denySDK("client not configured")
	}
	return c.RT.Execute(ctx, req)
}

// HTTPClient calls a remote Loom HTTP adapter (POST /v1/execute).
// Credentials are sent as Authorization: Bearer; never logs tokens.
type HTTPClient struct {
	BaseURL    string
	HTTPClient *http.Client
	// Token is the default bearer token (optional per-call override via Request.Credentials).
	Token string
	// UserAgent optional.
	UserAgent string
	// MaxBodyBytes caps response bodies (default 1 MiB).
	MaxBodyBytes int64
}

// NewHTTPClient creates a remote client. baseURL e.g. http://127.0.0.1:8080
func NewHTTPClient(baseURL, token string) *HTTPClient {
	return &HTTPClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		MaxBodyBytes: 1 << 20,
	}
}

type executeBody struct {
	Operation      string                `json:"operation"`
	Boundary       string                `json:"boundary"`
	Input          map[string]any        `json:"input"`
	Fields         []string              `json:"fields,omitempty"`
	IdempotencyKey string                `json:"idempotency_key,omitempty"`
	ApprovalToken  string                `json:"approval_token,omitempty"`
	Resource       *core.ResourceRef     `json:"resource,omitempty"`
	Metadata       map[string]string     `json:"metadata,omitempty"`
	Delegation     *core.DelegationChain `json:"delegation,omitempty"`
}

// Call posts to /v1/execute.
func (c *HTTPClient) Call(ctx context.Context, req core.Request) (core.Response, error) {
	if c == nil || c.BaseURL == "" {
		return denySDK("http client not configured"), fmt.Errorf("loom: http client not configured")
	}
	token := req.Credentials.Token
	if token == "" {
		token = c.Token
	}
	body := executeBody{
		Operation:      req.Operation,
		Boundary:       string(req.Boundary),
		Input:          req.Input,
		Fields:         req.Fields,
		IdempotencyKey: req.IdempotencyKey,
		ApprovalToken:  req.ApprovalToken,
		Resource:       req.Resource,
		Metadata:       req.Metadata,
		Delegation:     req.Delegation,
	}
	if body.Metadata == nil {
		body.Metadata = map[string]string{}
	}
	body.Metadata["adapter"] = "sdk-go-http"
	raw, err := json.Marshal(body)
	if err != nil {
		return denySDK(err.Error()), err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/execute", bytes.NewReader(raw))
	if err != nil {
		return denySDK(err.Error()), err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(core.ProtocolHeader, core.ProtocolVersion)
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	if req.TraceID != "" {
		httpReq.Header.Set("X-Trace-Id", req.TraceID)
	}
	if c.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.UserAgent)
	}
	return c.doJSON(ctx, httpReq)
}

// Manifest fetches GET /.well-known/loom.json (unauthenticated discovery).
func (c *HTTPClient) Manifest(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, "/.well-known/loom.json", false)
}

// OpenAPI fetches GET /v1/openapi.json (capability-filtered; uses client token).
func (c *HTTPClient) OpenAPI(ctx context.Context) (map[string]any, error) {
	return c.getJSON(ctx, "/v1/openapi.json", true)
}

// CatalogSpec calls the governed catalog.spec operation and returns tool specs.
func (c *HTTPClient) CatalogSpec(ctx context.Context, boundary string) (core.Response, error) {
	return c.Call(ctx, core.Request{
		Operation:   "catalog.spec",
		Boundary:    core.BoundaryID(boundary),
		Credentials: core.Credentials{Scheme: "bearer", Token: c.Token},
		Input:       map[string]any{},
	})
}

// MCP posts one JSON-RPC message to POST /mcp.
// Bearer is taken from Token unless overridden.
func (c *HTTPClient) MCP(ctx context.Context, rpcReq map[string]any) (map[string]any, error) {
	if c == nil || c.BaseURL == "" {
		return nil, fmt.Errorf("loom: http client not configured")
	}
	raw, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/mcp", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(core.ProtocolHeader, core.ProtocolVersion)
	if c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.UserAgent)
	}
	body, err := c.doRaw(httpReq)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return map[string]any{}, nil // notification / 204
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("loom: invalid mcp response: %w", err)
	}
	return out, nil
}

func (c *HTTPClient) getJSON(ctx context.Context, path string, auth bool) (map[string]any, error) {
	if c == nil || c.BaseURL == "" {
		return nil, fmt.Errorf("loom: http client not configured")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if auth && c.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	}
	httpReq.Header.Set(core.ProtocolHeader, core.ProtocolVersion)
	if c.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.UserAgent)
	}
	body, err := c.doRaw(httpReq)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("loom: invalid json: %w", err)
	}
	return out, nil
}

func (c *HTTPClient) doJSON(_ context.Context, httpReq *http.Request) (core.Response, error) {
	body, err := c.doRaw(httpReq)
	if err != nil {
		return denySDK(err.Error()), err
	}
	var out core.Response
	if err := json.Unmarshal(body, &out); err != nil {
		return denySDK("invalid response"), fmt.Errorf("loom: invalid response: %w", err)
	}
	return out, nil
}

func (c *HTTPClient) doRaw(httpReq *http.Request) ([]byte, error) {
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	limit := c.MaxBodyBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	return io.ReadAll(io.LimitReader(res.Body, limit))
}

func denySDK(msg string) core.Response {
	return core.Response{
		Allowed:  false,
		Decision: core.DecisionDeny,
		Denial:   core.NewDenial("sdk", core.ReasonInternal, msg, nil),
	}
}
