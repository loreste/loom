# Loom Schema

Loom Schema is a deliberately bounded, JSON-shaped contract used by operation
input and output guardrails. It is not a claim of full compatibility with a
JSON Schema draft. Unknown keywords fail closed during validation.

## Supported keywords

Loom supports:

- `type`: `object`, `array`, `string`, `number`, `integer`, `boolean`, or
  `null`;
- `properties`, `required`, `additionalProperties`, and `items`;
- `enum` and `const`;
- `minLength`, `maxLength`, and `pattern` for strings;
- `minimum` and `maximum` for numbers; and
- `minItems`, `maxItems`, and `uniqueItems` for arrays.

Schemas may be nested through `properties` and `items`. `pattern` uses Go's
RE2 regular-expression implementation. String lengths count Unicode runes.
Numbers are compared as exact decimal values; the validator does not use
floating-point arithmetic.

## Rejected or unsupported features

The following are rejected: `$ref`, `definitions`, `$defs`, `oneOf`, `anyOf`,
`allOf`, `not`, `if`, `then`, `else`, `format`, `multipleOf`, exclusive numeric
bounds, pattern properties, tuple-style `items`, and every unlisted keyword.
Reference resolution is intentionally not performed.

## Resource limits

Validation is bounded regardless of the caller-supplied schema:

| Limit | Maximum |
| --- | ---: |
| Schema/value nesting depth | 32 |
| Visited value nodes | 10,000 |
| Object properties | 1,000 |
| Array items | 10,000 |
| String Unicode runes | 1,000,000 |
| Regular-expression source bytes | 256 |
| `enum` or `required` entries | 1,000 |

`maxLength` and `maxItems` cannot exceed the corresponding Loom limit. Minimum
values cannot exceed maximum values. These limits are part of the protocol
contract and should be reviewed with compatibility tests when changed.

Declare only the keywords supported by the server version you target. There is
no `$schema` URI or `$ref` negotiation in the current protocol.

Input schema failures deny before the handler runs. Output schema failures
return no output and are recorded as enforcement failures.
