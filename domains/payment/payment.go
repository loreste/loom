// Package payment registers governed payment operations.
package payment

import (
	"fmt"

	"github.com/loreste/loom/core"
)

// CaptureInput schema constants.
const OpCapture = "payment.capture"
const OpRefund = "payment.refund"

// Register adds payment operations to the registry.
func Register(reg *core.Registry) error {
	if reg == nil {
		return fmt.Errorf("%w: nil registry", core.ErrInvalidArgument)
	}
	captureSchema := []byte(`{
		"type":"object",
		"properties":{
			"amount":{"type":"number","minimum":0.01,"maximum":1000000},
			"currency":{"type":"string","minLength":3,"maxLength":3,"pattern":"^[A-Z]{3}$"},
			"merchant_id":{"type":"string","minLength":1,"maxLength":64}
		},
		"required":["amount","currency","merchant_id"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:            OpCapture,
		Description:     "Capture a payment",
		InputSchema:     captureSchema,
		Permissions:     []string{"payment.capture"},
		Resources:       []string{"payment"},
		Risk:            core.RiskHigh,
		Effects:         []core.Effect{core.EffectMoney, core.EffectWrite},
		Approval:        core.ApprovalPolicy{MinRisk: core.RiskHigh},
		Idempotency:     core.IdempotencyPolicy{Required: true, TTLSeconds: 86400},
		SensitiveFields: []string{"pan", "cvv", "raw_processor_payload"},
		Limits:          map[string]int64{"amount": 10000},
	}, handleCapture); err != nil {
		return err
	}

	refundSchema := []byte(`{
		"type":"object",
		"properties":{
			"amount":{"type":"number","minimum":0.01,"maximum":1000000},
			"currency":{"type":"string","minLength":3,"maxLength":3,"pattern":"^[A-Z]{3}$"},
			"payment_id":{"type":"string","minLength":1,"maxLength":64},
			"reason":{"type":"string","maxLength":200}
		},
		"required":["amount","currency","payment_id"],
		"additionalProperties":false
	}`)
	return reg.Register(&core.Operation{
		Name:            OpRefund,
		Description:     "Refund a payment",
		InputSchema:     refundSchema,
		Permissions:     []string{"payment.refund"},
		Resources:       []string{"payment"},
		Risk:            core.RiskCritical,
		Effects:         []core.Effect{core.EffectMoney, core.EffectWrite},
		Approval:        core.ApprovalPolicy{Required: true},
		Idempotency:     core.IdempotencyPolicy{Required: true, TTLSeconds: 86400},
		SensitiveFields: []string{"pan", "cvv"},
	}, handleRefund)
}

func handleCapture(ec *core.ExecutionContext) (*core.Result, error) {
	currency, _ := ec.Input["currency"].(string)
	amount, err := core.ParseMoney(ec.Input["amount"], currency)
	if err != nil {
		return nil, fmt.Errorf("amount: %w", err)
	}
	merchant, _ := ec.Input["merchant_id"].(string)
	// Simulated capture — real systems call PSP behind network guardrails.
	id := "pay_" + ec.TraceID[:8]
	return &core.Result{
		Output: map[string]any{
			"payment_id":  id,
			"status":      "captured",
			"amount":      amount,
			"currency":    currency,
			"merchant_id": merchant,
			// must be stripped if present
			"raw_processor_payload": map[string]any{"secret": "sk-should-not-leak-xxxxxxxxxxx"},
		},
		EffectsActual: []core.Effect{core.EffectMoney, core.EffectWrite},
	}, nil
}

func handleRefund(ec *core.ExecutionContext) (*core.Result, error) {
	currency, _ := ec.Input["currency"].(string)
	amount, err := core.ParseMoney(ec.Input["amount"], currency)
	if err != nil {
		return nil, fmt.Errorf("amount: %w", err)
	}
	pid, _ := ec.Input["payment_id"].(string)
	return &core.Result{
		Output: map[string]any{
			"refund_id":  "ref_" + ec.TraceID[:8],
			"payment_id": pid,
			"status":     "refunded",
			"amount":     amount,
		},
		EffectsActual: []core.Effect{core.EffectMoney, core.EffectWrite},
	}, nil
}
