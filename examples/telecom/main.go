// Command telecom demonstrates a production-shaped, multi-tenant telecom
// provisioning surface. Every action is an exact, versioned Loom operation;
// high-risk changes require a single-use approval before the handler runs.
//
// This example uses process-local stores for portability. Production deploys
// must use PostgreSQL execution/approval/idempotency/audit stores, PostgreSQL
// RLS, shared Redis quotas, and a real provider reconciler.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/loreste/loom/bootstrap"
	"github.com/loreste/loom/core"
	"github.com/loreste/loom/identity"
	"github.com/loreste/loom/policy"
	"github.com/loreste/loom/resource"
)

const (
	operatorID  = core.PrincipalID("svc:telecom-operator")
	operatorCap = "telecom.provision"
	boundary    = core.BoundaryID("tenant-a")
)

type telecomOperation struct {
	name     string
	resource string
	approval bool
	risk     core.RiskLevel
	effects  []core.Effect
}

var telecomOperations = []telecomOperation{
	{name: "telecom.sip_trunk.create", resource: "sip_trunk", risk: core.RiskMedium, effects: []core.Effect{core.EffectWrite}},
	{name: "telecom.sip_trunk.modify", resource: "sip_trunk", approval: true, risk: core.RiskHigh, effects: []core.Effect{core.EffectWrite}},
	{name: "telecom.did.assign", resource: "did", approval: true, risk: core.RiskHigh, effects: []core.Effect{core.EffectWrite}},
	{name: "telecom.routing.modify", resource: "routing", approval: true, risk: core.RiskHigh, effects: []core.Effect{core.EffectWrite}},
	{name: "telecom.credit.change", resource: "credit_account", approval: true, risk: core.RiskCritical, effects: []core.Effect{core.EffectMoney, core.EffectAdmin}},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	token := strings.TrimSpace(os.Getenv("LOOM_TELECOM_TOKEN"))
	if token == "" {
		return fmt.Errorf("LOOM_TELECOM_TOKEN is required")
	}
	p, err := newTelecomPlatform(token)
	if err != nil {
		return err
	}
	defer p.Close()

	resourceRef := &core.ResourceRef{Type: "sip_trunk", ID: "trunk-100"}
	created := execute(ctx, p, token, telecomOperations[0].name, resourceRef, map[string]any{"customer_id": "customer-100", "carrier": "carrier-a"}, "")
	printResponse("create SIP trunk", created)

	approvalToken := "telecom-approval-demo"
	if err := p.IssueApproval(approvalToken, operatorID, "telecom.credit.change", boundary, core.RiskCritical, 10*time.Minute); err != nil {
		return err
	}
	changed := execute(ctx, p, token, "telecom.credit.change", &core.ResourceRef{Type: "credit_account", ID: "acct-100"}, map[string]any{"delta": "100.00", "amount": "100.00", "currency": "USD", "reason": "contract renewal"}, approvalToken)
	printResponse("approved credit change", changed)
	return nil
}

func newTelecomPlatform(token string) (*bootstrap.Platform, error) {
	p, err := bootstrap.NewPlatform(bootstrap.Config{
		PolicySyncInterval:       -1,
		DisableSeedPolicyPublish: true,
		DemoTokens:               map[string]string{string(operatorID): token},
	})
	if err != nil {
		return nil, err
	}
	if err := p.Boundary.Grant(operatorID, boundary); err != nil {
		p.Close()
		return nil, err
	}
	if err := p.Memory.Register(identity.StaticPrincipal{ID: operatorID, Token: token, Type: "service", Boundary: boundary, Capabilities: []string{operatorCap}}); err != nil {
		p.Close()
		return nil, err
	}
	for _, item := range telecomOperations {
		op := &core.Operation{
			Name:            item.name,
			Version:         "1",
			Description:     "governed telecom provisioning action",
			Permissions:     []string{operatorCap},
			Resources:       []string{item.resource},
			Risk:            item.risk,
			Effects:         item.effects,
			Approval:        core.ApprovalPolicy{Required: item.approval},
			Idempotency:     core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
			SensitiveFields: []string{"customer_id", "delta"},
		}
		if err := p.Registry.Register(op, telecomHandler(item.name)); err != nil {
			p.Close()
			return nil, err
		}
		if err := p.Policy.AddRule(policy.Rule{Principal: operatorID, Boundary: boundary, Operation: item.name, OperationVersion: "1", Permissions: []string{operatorCap}, Priority: 100}); err != nil {
			p.Close()
			return nil, err
		}
		if err := p.Resources.Grant(resource.Rule{Principal: operatorID, Boundary: boundary, Type: item.resource, ID: "*", Operations: []string{item.name}}); err != nil {
			p.Close()
			return nil, err
		}
		if err := p.Fields.GrantFields(operatorID, boundary, item.name, []string{"operation", "resource", "status", "provider_reference", "tenant_id", "amount", "currency"}); err != nil {
			p.Close()
			return nil, err
		}
		if err := p.Fields.GrantInputFields(operatorID, boundary, item.name, []string{"*", "customer_id", "delta"}); err != nil {
			p.Close()
			return nil, err
		}
	}
	return p, nil
}

func telecomHandler(operation string) core.Handler {
	return func(ec *core.ExecutionContext) (*core.Result, error) {
		resourceID := ""
		if ec.Resource != nil {
			resourceID = ec.Resource.ID
		}
		output := map[string]any{
			"operation":          operation,
			"resource":           resourceID,
			"status":             "accepted",
			"provider_reference": "provider-" + resourceID,
			"tenant_id":          string(ec.Boundary),
		}
		if value, ok := ec.Input["amount"]; ok {
			output["amount"] = value
		}
		if value, ok := ec.Input["currency"]; ok {
			output["currency"] = value
		}
		return &core.Result{Output: output, EffectsActual: ec.Operation.Effects}, nil
	}
}

func execute(ctx context.Context, p *bootstrap.Platform, token, operation string, resourceRef *core.ResourceRef, input map[string]any, approval string) core.Response {
	return p.Runtime.Execute(ctx, core.Request{
		Operation:        operation,
		OperationVersion: "1",
		Credentials:      core.Credentials{Scheme: "bearer", Token: token},
		Boundary:         boundary,
		Resource:         resourceRef,
		Input:            input,
		ApprovalToken:    approval,
		IdempotencyKey:   operation + "-" + resourceRef.ID,
	})
}

func printResponse(label string, response core.Response) {
	encoded, _ := json.MarshalIndent(response, "", "  ")
	fmt.Printf("== %s ==\n%s\n", label, encoded)
}
