package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/loreste/loom/core"
)

const (
	defaultMaxPolicyBytes   = 1 << 20 // 1 MiB
	defaultMaxPolicyRules   = 10_000
	defaultMaxStringLen     = 512
	defaultMaxArrayLen      = 256
	defaultMaxPermissions   = 64
	defaultMaxEffects       = 16
)

// Limits bounds policy document size and rule shape. Zero values use defaults.
type Limits struct {
	MaxBytes       int
	MaxRules       int
	MaxStringLen   int
	MaxArrayLen    int
	MaxPermissions int
	MaxEffects     int
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = defaultMaxPolicyBytes
	}
	if l.MaxRules <= 0 {
		l.MaxRules = defaultMaxPolicyRules
	}
	if l.MaxStringLen <= 0 {
		l.MaxStringLen = defaultMaxStringLen
	}
	if l.MaxArrayLen <= 0 {
		l.MaxArrayLen = defaultMaxArrayLen
	}
	if l.MaxPermissions <= 0 {
		l.MaxPermissions = defaultMaxPermissions
	}
	if l.MaxEffects <= 0 {
		l.MaxEffects = defaultMaxEffects
	}
	return l
}

var knownEffects = map[string]core.Effect{
	string(core.EffectRead):   core.EffectRead,
	string(core.EffectWrite):  core.EffectWrite,
	string(core.EffectDelete): core.EffectDelete,
	string(core.EffectExec):   core.EffectExec,
	string(core.EffectMoney):  core.EffectMoney,
	string(core.EffectAdmin):  core.EffectAdmin,
	string(core.EffectAI):     core.EffectAI,
}

// strictDecode unmarshals JSON with unknown-field rejection, trailing-data
// rejection, and duplicate-key detection.
func strictDecode(data []byte, dest any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("%w: %v", core.ErrInvalidArgument, err)
	}
	// Reject a second JSON value after the document (whitespace-only is fine).
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON after policy document", core.ErrInvalidArgument)
	}
	return nil
}

// rejectDuplicateKeys walks the JSON token stream and fails if any object
// repeats a key at the same nesting level. encoding/json silently keeps the
// last value, which would hide security-policy typos.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkDuplicates(dec, 0)
}

func walkDuplicates(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return fmt.Errorf("%w: object key must be a string", core.ErrInvalidArgument)
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("%w: duplicate JSON key %q", core.ErrInvalidArgument, key)
				}
				seen[key] = struct{}{}
				if err := walkDuplicates(dec, depth+1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return fmt.Errorf("%w: malformed object", core.ErrInvalidArgument)
			}
		case '[':
			for dec.More() {
				if err := walkDuplicates(dec, depth+1); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return fmt.Errorf("%w: malformed array", core.ErrInvalidArgument)
			}
		default:
			return fmt.Errorf("%w: unexpected delimiter %v", core.ErrInvalidArgument, t)
		}
	case string, bool, float64, json.Number, nil:
		return nil
	default:
		return fmt.Errorf("%w: unexpected JSON token", core.ErrInvalidArgument)
	}
	return nil
}

func validateEffect(name string) (core.Effect, error) {
	effect, ok := knownEffects[strings.TrimSpace(name)]
	if !ok {
		return "", fmt.Errorf("%w: unsupported effect %q", core.ErrInvalidArgument, name)
	}
	return effect, nil
}

func boundString(label, value string, max int) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return "", fmt.Errorf("%w: %s exceeds %d characters", core.ErrInvalidArgument, label, max)
	}
	return value, nil
}
