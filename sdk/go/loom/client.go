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
}

// NewHTTPClient creates a remote client. baseURL e.g. http://127.0.0.1:8080
func NewHTTPClient(baseURL, token string) *HTTPClient {
	return &HTTPClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

type executeBody struct {
	Operation      string              `json:"operation"`
	Boundary       string              `json:"boundary"`
	Input          map[string]any      `json:"input"`
	Fields         []string            `json:"fields,omitempty"`
	IdempotencyKey string              `json:"idempotency_key,omitempty"`
	ApprovalToken  string              `json:"approval_token,omitempty"`
	Resource       *core.ResourceRef   `json:"resource,omitempty"`
	Metadata       map[string]string   `json:"metadata,omitempty"`
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
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	if req.TraceID != "" {
		httpReq.Header.Set("X-Trace-Id", req.TraceID)
	}
	if c.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.UserAgent)
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(httpReq)
	if err != nil {
		return denySDK(err.Error()), err
	}
	defer res.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return denySDK(err.Error()), err
	}
	var out core.Response
	if err := json.Unmarshal(respBody, &out); err != nil {
		return denySDK("invalid response"), fmt.Errorf("loom: invalid response: %w", err)
	}
	return out, nil
}

func denySDK(msg string) core.Response {
	return core.Response{
		Allowed:  false,
		Decision: core.DecisionDeny,
		Denial:   core.NewDenial("sdk", core.ReasonInternal, msg, nil),
	}
}
