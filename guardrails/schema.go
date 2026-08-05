package guardrails

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ValidateSchema validates a JSON-shaped value against Loom Schema.
// Loom intentionally implements a small, bounded schema contract rather than
// claiming compatibility with every JSON Schema keyword. Unsupported keywords
// fail closed during validation.
//
// Supported keywords: type, properties, required, additionalProperties, items,
// enum, const, minLength, maxLength, pattern, minimum, maximum, minItems,
// maxItems, and uniqueItems.
func ValidateSchema(document []byte, value any) error {
	var schema map[string]any
	dec := json.NewDecoder(strings.NewReader(string(document)))
	dec.UseNumber()
	if err := dec.Decode(&schema); err != nil || schema == nil {
		return fmt.Errorf("invalid schema document")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("schema document has trailing data")
	}
	budget := &schemaBudget{}
	if err := validateSchemaKeywords(schema); err != nil {
		return err
	}
	return validateSchemaValue(schema, value, 0, budget)
}

const (
	// MaxSchemaDepth bounds nested objects and arrays.
	MaxSchemaDepth = 32
	// MaxSchemaNodes bounds the number of values visited during validation.
	MaxSchemaNodes = 10_000
	// MaxSchemaProperties bounds object width, including undeclared fields.
	MaxSchemaProperties = 1_000
	// MaxSchemaArrayItems bounds arrays even when maxItems is omitted.
	MaxSchemaArrayItems = 10_000
	// MaxSchemaStringRunes bounds string length even when maxLength is omitted.
	MaxSchemaStringRunes = 1_000_000
	// MaxSchemaPatternBytes bounds regular-expression source length.
	MaxSchemaPatternBytes = 256
	// MaxSchemaCollectionItems bounds schema enum and required collections.
	MaxSchemaCollectionItems = 1_000
)

type schemaBudget struct{ nodes int }

var supportedSchemaKeywords = map[string]struct{}{
	"type": {}, "properties": {}, "required": {}, "additionalProperties": {},
	"items": {}, "enum": {}, "const": {}, "minLength": {}, "maxLength": {},
	"pattern": {}, "minimum": {}, "maximum": {}, "minItems": {},
	"maxItems": {}, "uniqueItems": {},
}

func validateSchemaKeywords(schema map[string]any) error {
	return validateSchemaKeywordsAtDepth(schema, 0)
}

func validateSchemaKeywordsAtDepth(schema map[string]any, depth int) error {
	if depth > MaxSchemaDepth {
		return fmt.Errorf("schema nesting limit exceeded")
	}
	for key := range schema {
		if _, ok := supportedSchemaKeywords[key]; !ok {
			return fmt.Errorf("unsupported schema keyword %q", key)
		}
	}
	if typ, ok := schema["type"]; ok {
		t, ok := typ.(string)
		if !ok || !validSchemaType(t) {
			return fmt.Errorf("unsupported schema type")
		}
	}
	if props, ok := schema["properties"]; ok {
		m, ok := props.(map[string]any)
		if !ok {
			return fmt.Errorf("properties must be an object")
		}
		if len(m) > MaxSchemaProperties {
			return fmt.Errorf("schema property limit exceeded")
		}
		for name, raw := range m {
			child, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("property %q has invalid schema", name)
			}
			if err := validateSchemaKeywordsAtDepth(child, depth+1); err != nil {
				return fmt.Errorf("property %q: %w", name, err)
			}
		}
	}
	if required, ok := schema["required"]; ok {
		items, ok := required.([]any)
		if !ok {
			return fmt.Errorf("required must be an array")
		}
		if len(items) > MaxSchemaCollectionItems {
			return fmt.Errorf("required collection limit exceeded")
		}
		for _, item := range items {
			name, ok := item.(string)
			if !ok || name == "" {
				return fmt.Errorf("required entries must be non-empty strings")
			}
		}
	}
	if additional, ok := schema["additionalProperties"]; ok {
		if _, ok := additional.(bool); !ok {
			return fmt.Errorf("additionalProperties must be boolean")
		}
	}
	if items, ok := schema["items"]; ok {
		child, ok := items.(map[string]any)
		if !ok {
			return fmt.Errorf("items must be a schema object")
		}
		if err := validateSchemaKeywordsAtDepth(child, depth+1); err != nil {
			return fmt.Errorf("items: %w", err)
		}
	}
	if pattern, ok := schema["pattern"]; ok {
		pat, ok := pattern.(string)
		if !ok {
			return fmt.Errorf("pattern must be a string")
		}
		if len(pat) > MaxSchemaPatternBytes {
			return fmt.Errorf("pattern too long")
		}
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("invalid pattern in schema")
		}
	}
	for _, key := range []string{"minLength", "maxLength", "minItems", "maxItems"} {
		if raw, ok := schema[key]; ok {
			if _, ok := exactNonNegativeInt(raw); !ok {
				return fmt.Errorf("%s must be a non-negative integer", key)
			}
		}
	}
	if n, ok := schemaInt(schema, "maxLength"); ok && n > MaxSchemaStringRunes {
		return fmt.Errorf("maxLength exceeds Loom Schema limit")
	}
	if n, ok := schemaInt(schema, "maxItems"); ok && n > MaxSchemaArrayItems {
		return fmt.Errorf("maxItems exceeds Loom Schema limit")
	}
	if min, ok := schemaInt(schema, "minLength"); ok {
		if max, exists := schemaInt(schema, "maxLength"); exists && min > max {
			return fmt.Errorf("minLength exceeds maxLength")
		}
	}
	if min, ok := schemaInt(schema, "minItems"); ok {
		if max, exists := schemaInt(schema, "maxItems"); exists && min > max {
			return fmt.Errorf("minItems exceeds maxItems")
		}
	}
	for _, key := range []string{"minimum", "maximum"} {
		if raw, ok := schema[key]; ok {
			if _, ok := exactNumber(raw); !ok {
				return fmt.Errorf("%s must be a number", key)
			}
		}
	}
	if unique, ok := schema["uniqueItems"]; ok {
		if _, ok := unique.(bool); !ok {
			return fmt.Errorf("uniqueItems must be boolean")
		}
	}
	if enum, ok := schema["enum"]; ok {
		items, ok := enum.([]any)
		if !ok {
			return fmt.Errorf("enum must be an array")
		}
		if len(items) > MaxSchemaCollectionItems {
			return fmt.Errorf("enum collection limit exceeded")
		}
	}
	return nil
}

func validSchemaType(t string) bool {
	switch t {
	case "object", "array", "string", "number", "integer", "boolean", "null":
		return true
	default:
		return false
	}
}

func validateSchemaValue(schema map[string]any, value any, depth int, budget *schemaBudget) error {
	if depth > MaxSchemaDepth {
		return fmt.Errorf("schema nesting limit exceeded")
	}
	budget.nodes++
	if budget.nodes > MaxSchemaNodes {
		return fmt.Errorf("schema value node limit exceeded")
	}
	if err := validateSchemaKeywords(schema); err != nil {
		return err
	}
	if raw, ok := schema["const"]; ok && !schemaValuesEqual(raw, value) {
		return fmt.Errorf("value differs from const")
	}
	if raw, ok := schema["enum"]; ok {
		items, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("enum must be an array")
		}
		matched := false
		for _, item := range items {
			if schemaValuesEqual(item, value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("value is not in enum")
		}
	}
	typ, _ := schema["type"].(string)
	switch typ {
	case "object":
		m, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		return validateSchemaObject(schema, m, depth, budget)
	case "array":
		arr, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected array")
		}
		if n, ok := schemaInt(schema, "minItems"); ok && len(arr) < n {
			return fmt.Errorf("too few items")
		}
		if len(arr) > MaxSchemaArrayItems {
			return fmt.Errorf("array item limit exceeded")
		}
		if n, ok := schemaInt(schema, "maxItems"); ok && len(arr) > n {
			return fmt.Errorf("too many items")
		}
		if unique, _ := schema["uniqueItems"].(bool); unique && !uniqueValues(arr) {
			return fmt.Errorf("array items must be unique")
		}
		if raw, ok := schema["items"]; ok {
			items := raw.(map[string]any)
			for _, item := range arr {
				if err := validateSchemaValue(items, item, depth+1, budget); err != nil {
					return err
				}
			}
		}
	case "string":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string")
		}
		length := utf8.RuneCountInString(s)
		if length > MaxSchemaStringRunes {
			return fmt.Errorf("string rune limit exceeded")
		}
		if n, ok := schemaInt(schema, "minLength"); ok && length < n {
			return fmt.Errorf("string too short")
		}
		if n, ok := schemaInt(schema, "maxLength"); ok && length > n {
			return fmt.Errorf("string too long")
		}
		if pat, ok := schema["pattern"].(string); ok && pat != "" {
			re := regexp.MustCompile(pat)
			if !re.MatchString(s) {
				return fmt.Errorf("pattern mismatch")
			}
		}
	case "number", "integer":
		n, ok := exactNumber(value)
		if !ok {
			return fmt.Errorf("expected number")
		}
		if typ == "integer" && n.Denom().Cmp(big.NewInt(1)) != 0 {
			return fmt.Errorf("expected integer")
		}
		if min, ok := exactNumber(schema["minimum"]); ok && n.Cmp(min) < 0 {
			return fmt.Errorf("below minimum")
		}
		if max, ok := exactNumber(schema["maximum"]); ok && n.Cmp(max) > 0 {
			return fmt.Errorf("above maximum")
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean")
		}
	case "null":
		if value != nil {
			return fmt.Errorf("expected null")
		}
	case "":
		// A schema with constraints but no type is valid.
	default:
		return fmt.Errorf("unsupported schema type %q", typ)
	}
	return nil
}

func validateSchemaObject(schema map[string]any, input map[string]any, depth int, budget *schemaBudget) error {
	if len(input) > MaxSchemaProperties {
		return fmt.Errorf("object property limit exceeded")
	}
	if raw, ok := schema["required"]; ok {
		for _, item := range raw.([]any) {
			name := item.(string)
			if _, exists := input[name]; !exists {
				return fmt.Errorf("missing required field %q", name)
			}
		}
	}
	props, _ := schema["properties"].(map[string]any)
	if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
		for name := range input {
			if _, exists := props[name]; !exists {
				return fmt.Errorf("additional property %q not allowed", name)
			}
		}
	}
	for name, value := range input {
		if raw, exists := props[name]; exists {
			if err := validateSchemaValue(raw.(map[string]any), value, depth+1, budget); err != nil {
				return fmt.Errorf("field %q: %w", name, err)
			}
		}
	}
	return nil
}

func schemaInt(schema map[string]any, key string) (int, bool) {
	return exactNonNegativeInt(schema[key])
}

func exactNonNegativeInt(value any) (int, bool) {
	n, ok := exactNumber(value)
	if !ok || n.Sign() < 0 || n.Denom().Cmp(big.NewInt(1)) != 0 || !n.Num().IsInt64() {
		return 0, false
	}
	i := n.Num().Int64()
	if int64(int(i)) != i {
		return 0, false
	}
	return int(i), true
}

func exactNumber(value any) (*big.Rat, bool) {
	var text string
	switch n := value.(type) {
	case json.Number:
		text = n.String()
	case string:
		text = n
	case int:
		text = strconv.Itoa(n)
	case int64:
		text = strconv.FormatInt(n, 10)
	case float64:
		text = strconv.FormatFloat(n, 'f', -1, 64)
	case float32:
		text = strconv.FormatFloat(float64(n), 'f', -1, 32)
	default:
		return nil, false
	}
	r, ok := new(big.Rat).SetString(strings.TrimSpace(text))
	return r, ok && r != nil
}

func schemaValuesEqual(a, b any) bool {
	ra, oka := exactNumber(a)
	rb, okb := exactNumber(b)
	if oka && okb {
		return ra.Cmp(rb) == 0
	}
	return reflect.DeepEqual(a, b)
}

func uniqueValues(items []any) bool {
	for i := range items {
		for j := i + 1; j < len(items); j++ {
			if schemaValuesEqual(items[i], items[j]) {
				return false
			}
		}
	}
	return true
}
