package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	loomcli "github.com/loreste/loom/adapters/cli"
	loomgql "github.com/loreste/loom/adapters/graphql"
	loomgrpc "github.com/loreste/loom/adapters/grpc"
	loomv1 "github.com/loreste/loom/adapters/grpc/gen/loom/v1"
	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/adapters/mcp"
	"github.com/loreste/loom/adapters/weft"
	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/internal/testtokens"
	"google.golang.org/grpc/metadata"
)

type semanticResponse struct {
	Allowed          bool
	Decision         string
	Outcome          string
	OperationVersion string
	Output           string
}

func semantic(resp core.Response) semanticResponse {
	output, _ := json.Marshal(resp.Output)
	return semanticResponse{
		Allowed:          resp.Allowed,
		Decision:         resp.Decision.String(),
		Outcome:          resp.Outcome.String(),
		OperationVersion: resp.OperationVersion,
		Output:           string(output),
	}
}

func TestAdaptersResolveIdentically(t *testing.T) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               testtokens.Demo(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx := context.Background()
	resource := &core.ResourceRef{Type: "document", ID: "1"}
	input := map[string]any{"id": "1"}
	request := core.Request{
		Operation:        "document.read",
		OperationVersion: "1",
		Credentials:      core.Credentials{Scheme: "bearer", Token: "alice-secret-token"},
		Boundary:         "dev",
		Resource:         resource,
		Input:            input,
	}
	want := semantic(p.Runtime.Execute(ctx, request))
	if !want.Allowed || want.OperationVersion != "1" {
		t.Fatalf("native execution must allow selected version: %+v", want)
	}

	weftResponse, err := weft.New(p.Runtime).Invoke(ctx, weft.StepCall{
		Operation:        "document.read",
		OperationVersion: "1",
		BearerToken:      "alice-secret-token",
		Boundary:         "dev",
		Resource:         resource,
		Input:            input,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSame(t, "weft", want, semantic(weftResponse))

	mcpResponse, err := mcp.New(p.Runtime).Call(ctx, mcp.ToolCall{
		Name:             "document.read",
		OperationVersion: "1",
		BearerToken:      "alice-secret-token",
		Boundary:         "dev",
		Resource:         resource,
		Arguments:        input,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSame(t, "mcp", want, semantic(mcpResponse))

	httpServer, err := loomhttp.NewServer(p.Runtime, loomhttp.ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	httpBody := `{"operation":"document.read","operation_version":"1","boundary":"dev","input":{"id":"1"},"resource":{"type":"document","id":"1"}}`
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewBufferString(httpBody))
	httpReq.Header.Set("Authorization", "Bearer alice-secret-token")
	httpRR := httptest.NewRecorder()
	httpServer.Handler().ServeHTTP(httpRR, httpReq)
	if httpRR.Code != http.StatusOK {
		t.Fatalf("http status %d: %s", httpRR.Code, httpRR.Body.String())
	}
	var httpResponse core.Response
	if err := json.Unmarshal(httpRR.Body.Bytes(), &httpResponse); err != nil {
		t.Fatal(err)
	}
	assertSame(t, "http", want, semantic(httpResponse))

	graphqlQuery := `mutation($in: ExecuteInput!) { execute(input: $in) { allowed decision outcome operationVersion output } }`
	graphqlVars := map[string]any{"in": map[string]any{
		"operation":        "document.read",
		"operationVersion": "1",
		"boundary":         "dev",
		"input":            `{"id":"1"}`,
		"resource":         map[string]any{"type": "document", "id": "1"},
	}}
	graphqlResponse, err := loomgql.Do(loomgql.WithToken(ctx, "alice-secret-token"), p.Runtime, graphqlQuery, graphqlVars)
	if err != nil {
		t.Fatal(err)
	}
	if len(graphqlResponse.Errors) != 0 {
		t.Fatalf("graphql errors: %v", graphqlResponse.Errors)
	}
	graphqlData := graphqlResponse.Data.(map[string]any)["execute"].(map[string]any)
	graphqlOutputValue := graphqlData["output"]
	if encoded, ok := graphqlOutputValue.(string); ok {
		var decoded any
		if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
			t.Fatal(err)
		}
		graphqlOutputValue = decoded
	}
	graphqlOutput, _ := json.Marshal(graphqlOutputValue)
	assertSame(t, "graphql", want, semanticResponse{
		Allowed:          graphqlData["allowed"].(bool),
		Decision:         graphqlData["decision"].(string),
		Outcome:          graphqlData["outcome"].(string),
		OperationVersion: graphqlData["operationVersion"].(string),
		Output:           string(graphqlOutput),
	})

	grpcServer, err := loomgrpc.NewServer(p.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	grpcCtx := metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer alice-secret-token"))
	grpcResponse, err := grpcServer.Execute(grpcCtx, &loomv1.ExecuteRequest{
		Operation:        "document.read",
		OperationVersion: "1",
		Boundary:         "dev",
		InputJson:        `{"id":"1"}`,
		ResourceType:     "document",
		ResourceId:       "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertSame(t, "grpc", want, semanticResponse{
		Allowed:          grpcResponse.Allowed,
		Decision:         grpcResponse.Decision,
		Outcome:          grpcResponse.Outcome,
		OperationVersion: grpcResponse.OperationVersion,
		Output:           grpcResponse.OutputJson,
	})

	var cliOutput bytes.Buffer
	cli := loomcli.New(p.Runtime)
	cli.Out = &cliOutput
	if code := cli.Run(ctx, []string{
		"exec", "document.read",
		"--operation-version=1",
		"--boundary=dev",
		"--token=alice-secret-token",
		"--resource-type=document",
		"--resource-id=1",
		`--input={"id":"1"}`,
	}); code != 0 {
		t.Fatalf("cli exit code %d: %s", code, cliOutput.String())
	}
	var cliResponse core.Response
	if err := json.Unmarshal(cliOutput.Bytes(), &cliResponse); err != nil {
		t.Fatal(err)
	}
	assertSame(t, "cli", want, semantic(cliResponse))
}

func assertSame(t *testing.T, adapter string, want, got semanticResponse) {
	t.Helper()
	if want != got {
		t.Fatalf("%s diverged from native response:\nwant: %+v\ngot:  %+v", adapter, want, got)
	}
}
