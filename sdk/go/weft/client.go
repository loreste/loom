// Package weft provides a small Go SDK for invoking Loom from Weft workflows.
// Every call is translated to the existing Weft adapter and reaches
// runtime.Runtime.Execute; the SDK does not create a privilege path.
package weft

import (
	"context"
	"fmt"

	adapter "github.com/loreste/loom/adapters/weft"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/runtime"
)

type StepCall = adapter.StepCall
type BatchResult = adapter.BatchResult
type BatchOptions = adapter.BatchOptions

type Client struct{ adapter *adapter.Adapter }

func New(rt *runtime.Runtime) *Client { return &Client{adapter: adapter.New(rt)} }

func (c *Client) Invoke(ctx context.Context, call StepCall) (core.Response, error) {
	if c == nil || c.adapter == nil {
		return core.Response{}, fmt.Errorf("weft sdk: client not configured")
	}
	return c.adapter.Invoke(ctx, call)
}

func (c *Client) BatchInvoke(ctx context.Context, calls []StepCall, options BatchOptions) (BatchResult, error) {
	if c == nil || c.adapter == nil {
		return BatchResult{}, fmt.Errorf("weft sdk: client not configured")
	}
	return c.adapter.BatchInvoke(ctx, calls, options)
}
