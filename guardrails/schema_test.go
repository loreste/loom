package guardrails_test

import (
	"testing"

	"github.com/loreste/loom/guardrails"
)

func TestValidateSchemaRejectsUnsupportedKeywords(t *testing.T) {
	err := guardrails.ValidateSchema([]byte(`{"type":"object","additionalProperties":false,"oneOf":[]}`), map[string]any{})
	if err == nil {
		t.Fatal("unsupported schema keyword must fail closed")
	}
}

func TestValidateSchemaValidatesNestedOutput(t *testing.T) {
	schema := []byte(`{"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{"type":"array","minItems":1,"items":{"type":"object","required":["id"],"additionalProperties":false,"properties":{"id":{"type":"string"}}}}}}`)
	good := map[string]any{"items": []any{map[string]any{"id": "a"}}}
	if err := guardrails.ValidateSchema(schema, good); err != nil {
		t.Fatalf("valid nested output rejected: %v", err)
	}
	bad := map[string]any{"items": []any{map[string]any{"id": "a", "secret": "x"}}}
	if err := guardrails.ValidateSchema(schema, bad); err == nil {
		t.Fatal("unexpected nested output field must be rejected")
	}
}
