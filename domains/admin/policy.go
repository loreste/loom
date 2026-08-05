package admin

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/loreste/loom/core"
	"github.com/loreste/loom/policy"
)

const (
	OpPolicyPublish = "policy.publish"
	OpPolicyGet     = "policy.get"
)

// PolicyDeps for policy admin ops.
type PolicyDeps struct {
	Source policy.Source
	// Engine optional: after publish, apply immediately on this node.
	Engine *policy.MemoryEngine
	// Syncer optional: update applied version tracking.
	OnPublish func(doc *policy.Document)
}

// RegisterPolicy adds policy.publish / policy.get when source is configured.
func RegisterPolicy(reg *core.Registry, deps PolicyDeps) error {
	if reg == nil || deps.Source == nil {
		return fmt.Errorf("%w: registry and policy source required", core.ErrInvalidArgument)
	}
	pubSchema := []byte(`{
		"type":"object",
		"properties":{
			"version":{"type":"integer","minimum":1},
			"id":{"type":"string","maxLength":64},
			"rules":{"type":"array","minItems":0}
		},
		"required":["version","rules"],
		"additionalProperties":false
	}`)
	if err := reg.Register(&core.Operation{
		Name:        OpPolicyPublish,
		Description: "Publish a versioned policy document to the distributed store",
		InputSchema: pubSchema,
		Permissions: []string{"policy.publish"},
		Risk:        core.RiskCritical,
		Effects:     []core.Effect{core.EffectAdmin, core.EffectWrite},
		Approval:    core.ApprovalPolicy{Required: true},
		Idempotency: core.IdempotencyPolicy{Required: true, TTLSeconds: 3600},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handlePolicyPublish(ec, deps)
	}); err != nil {
		return err
	}

	getSchema := []byte(`{"type":"object","properties":{"id":{"type":"string"}},"additionalProperties":false}`)
	return reg.Register(&core.Operation{
		Name:        OpPolicyGet,
		Description: "Read the current distributed policy document metadata + rules",
		InputSchema: getSchema,
		Permissions: []string{"policy.get"},
		Risk:        core.RiskMedium,
		Effects:     []core.Effect{core.EffectRead, core.EffectAdmin},
	}, func(ec *core.ExecutionContext) (*core.Result, error) {
		return handlePolicyGet(ec, deps)
	})
}

func handlePolicyPublish(ec *core.ExecutionContext, deps PolicyDeps) (*core.Result, error) {
	ver, ok := asInt64(ec.Input["version"])
	if !ok || ver < 1 {
		return nil, fmt.Errorf("version required")
	}
	id, _ := ec.Input["id"].(string)
	if id == "" {
		id = "default"
	}
	// rules come as []any from JSON
	rawRules, err := json.Marshal(ec.Input["rules"])
	if err != nil {
		return nil, err
	}
	var rules []policy.Rule
	if err := json.Unmarshal(rawRules, &rules); err != nil {
		return nil, fmt.Errorf("invalid rules: %w", err)
	}
	doc := &policy.Document{
		Version:   ver,
		ID:        id,
		Rules:     rules,
		UpdatedAt: time.Now().UTC(),
	}
	// Validate by parse round-trip
	b, err := doc.Bytes()
	if err != nil {
		return nil, err
	}
	doc, err = policy.ParseDocument(b)
	if err != nil {
		return nil, err
	}
	doc.Version = ver
	doc.ID = id

	if err := deps.Source.Publish(ec.Ctx, doc); err != nil {
		return nil, err
	}
	if deps.Engine != nil {
		if err := deps.Engine.ReplaceRules(doc.Rules); err != nil {
			return nil, fmt.Errorf("published but local apply failed: %w", err)
		}
	}
	if deps.OnPublish != nil {
		deps.OnPublish(doc)
	}
	return &core.Result{Output: map[string]any{
		"status":     "published",
		"version":    ver,
		"id":         id,
		"rule_count": len(doc.Rules),
		"published_by": string(ec.Identity.ID),
	}}, nil
}

func handlePolicyGet(ec *core.ExecutionContext, deps PolicyDeps) (*core.Result, error) {
	doc, err := deps.Source.Load(ec.Ctx)
	if err != nil {
		return nil, err
	}
	// Return rules for admins with field grants
	return &core.Result{Output: map[string]any{
		"id":         doc.ID,
		"version":    doc.Version,
		"rule_count": len(doc.Rules),
		"rules":      doc.Rules,
		"updated_at": doc.UpdatedAt.UTC().Format(time.RFC3339),
	}}, nil
}

func asInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	default:
		return 0, false
	}
}
