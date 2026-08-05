package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	loomhttp "github.com/loreste/loom/adapters/http"
	"github.com/loreste/loom/app"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

func required(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func main() {
	operation, err := required("LOOM_CONTRACT_OPERATION")
	if err != nil {
		panic(err)
	}
	token, err := required("LOOM_CONTRACT_TOKEN")
	if err != nil {
		panic(err)
	}
	principal, err := required("LOOM_CONTRACT_PRINCIPAL")
	if err != nil {
		panic(err)
	}
	boundary, err := required("LOOM_CONTRACT_BOUNDARY")
	if err != nil {
		panic(err)
	}
	addr, err := required("LOOM_CONTRACT_ADDR")
	if err != nil {
		panic(err)
	}

	a, err := app.New(app.Config{})
	if err != nil {
		panic(err)
	}
	defer a.Close()
	operationSchema := json.RawMessage(`{"type":"object","additionalProperties":false}`)
	if err := a.Register(&core.Operation{
		Name: operation, InputSchema: operationSchema,
		Permissions: []string{operation}, Effects: []core.Effect{core.EffectRead},
	}, func(*core.ExecutionContext) (*core.Result, error) {
		return &core.Result{Output: map[string]any{"status": "ok"}}, nil
	}); err != nil {
		panic(err)
	}
	if err := a.AddUser(core.PrincipalID(principal), token, core.BoundaryID(boundary), []string{operation}); err != nil {
		panic(err)
	}
	if err := a.AllowPolicy(policy.Rule{Principal: core.PrincipalID(principal), Boundary: core.BoundaryID(boundary), Operation: operation}); err != nil {
		panic(err)
	}
	if err := a.AllowFields(core.PrincipalID(principal), core.BoundaryID(boundary), operation, []string{"status"}); err != nil {
		panic(err)
	}
	srv, err := loomhttp.NewServer(a.Runtime, loomhttp.ServerConfig{Addr: addr, Registry: a.Registry, Verifier: a.Verifier})
	if err != nil {
		panic(err)
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
