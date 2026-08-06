package core

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Money is an exact, non-negative monetary value.
//
// Units are whole currency units and Nanos is the fractional part in
// 10^-9 units. Currency is an uppercase three-letter code and is compared
// case-insensitively. The syntax alone does not establish that a code is an
// ISO-4217 currency; operations should use AllowedCurrencies when that
// distinction matters. Money is deliberately not represented by float64.
type Money struct {
	Units    int64  `json:"units"`
	Nanos    int32  `json:"nanos"`
	Currency string `json:"currency"`
}

// IsZero reports whether the amount is zero.
func (m Money) IsZero() bool { return m.Units == 0 && m.Nanos == 0 }

// Valid reports whether the value is canonical and usable for limits.
func (m Money) Valid() bool {
	return m.Units >= 0 && m.Nanos >= 0 && m.Nanos < 1_000_000_000 && validCurrency(m.Currency)
}

// CurrencyCode returns the canonical uppercase currency code.
func (m Money) CurrencyCode() string { return strings.ToUpper(strings.TrimSpace(m.Currency)) }

// MoneyDelta is a signed exact monetary adjustment. Money remains
// non-negative for payment amounts and ceilings; ledgers and reversals should
// use MoneyDelta instead of weakening those invariants.
//
// Negative values use negative Units and/or Nanos. Canonical values keep both
// components on the same side of zero, for example {-2, -500000000}.
type MoneyDelta struct {
	Units    int64  `json:"units"`
	Nanos    int32  `json:"nanos"`
	Currency string `json:"currency"`
}

// Valid reports whether the signed value is canonical.
func (d MoneyDelta) Valid() bool {
	if !validCurrency(d.Currency) || d.Nanos <= -1_000_000_000 || d.Nanos >= 1_000_000_000 {
		return false
	}
	return d.Units == 0 || d.Nanos == 0 || (d.Units > 0 && d.Nanos > 0) || (d.Units < 0 && d.Nanos < 0)
}

// Compare compares signed values with the same currency.
func (d MoneyDelta) Compare(other MoneyDelta) (int, error) {
	if !d.Valid() || !other.Valid() {
		return 0, fmt.Errorf("invalid money delta")
	}
	if !strings.EqualFold(d.Currency, other.Currency) {
		return 0, fmt.Errorf("currency mismatch")
	}
	if d.Units < other.Units || (d.Units == other.Units && d.Nanos < other.Nanos) {
		return -1, nil
	}
	if d.Units > other.Units || (d.Units == other.Units && d.Nanos > other.Nanos) {
		return 1, nil
	}
	return 0, nil
}

// CurrencyAllowed reports whether code is included in a case-insensitive
// explicit allow-list. An empty list means no list was configured.
func CurrencyAllowed(code string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	code = strings.ToUpper(strings.TrimSpace(code))
	if !validCurrency(code) {
		return false
	}
	for _, candidate := range allowed {
		if strings.EqualFold(code, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

// Compare compares values with the same currency.
func (m Money) Compare(other Money) (int, error) {
	if !m.Valid() || !other.Valid() {
		return 0, fmt.Errorf("invalid money value")
	}
	if !strings.EqualFold(m.Currency, other.Currency) {
		return 0, fmt.Errorf("currency mismatch")
	}
	if m.Units < other.Units || (m.Units == other.Units && m.Nanos < other.Nanos) {
		return -1, nil
	}
	if m.Units > other.Units || (m.Units == other.Units && m.Nanos > other.Nanos) {
		return 1, nil
	}
	return 0, nil
}

// ParseMoney parses a JSON-shaped amount exactly. Decimal strings and
// json.Number are preferred. float64 is accepted only after its shortest
// decimal representation is recovered; no floating-point arithmetic is used.
func ParseMoney(value any, currency string) (Money, error) {
	if s, ok := value.(string); ok {
		return parseMoneyString(s, currency)
	}
	if n, ok := value.(json.Number); ok {
		return parseMoneyString(n.String(), currency)
	}
	switch n := value.(type) {
	case int:
		return parseMoneyString(strconv.FormatInt(int64(n), 10), currency)
	case int8:
		return parseMoneyString(strconv.FormatInt(int64(n), 10), currency)
	case int16:
		return parseMoneyString(strconv.FormatInt(int64(n), 10), currency)
	case int32:
		return parseMoneyString(strconv.FormatInt(int64(n), 10), currency)
	case int64:
		return parseMoneyString(strconv.FormatInt(n, 10), currency)
	case uint:
		return parseMoneyString(strconv.FormatUint(uint64(n), 10), currency)
	case uint8:
		return parseMoneyString(strconv.FormatUint(uint64(n), 10), currency)
	case uint16:
		return parseMoneyString(strconv.FormatUint(uint64(n), 10), currency)
	case uint32:
		return parseMoneyString(strconv.FormatUint(uint64(n), 10), currency)
	case uint64:
		return parseMoneyString(strconv.FormatUint(n, 10), currency)
	case float32:
		return parseMoneyString(strconv.FormatFloat(float64(n), 'f', -1, 32), currency)
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return Money{}, fmt.Errorf("non-finite amount")
		}
		return parseMoneyString(strconv.FormatFloat(n, 'f', -1, 64), currency)
	default:
		return Money{}, fmt.Errorf("amount must be a decimal number or string")
	}
}

func parseMoneyString(value, currency string) (Money, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return Money{}, fmt.Errorf("amount must be a non-negative decimal")
	}
	if strings.ContainsAny(value, "eE") {
		return Money{}, fmt.Errorf("exponent notation is not accepted for money")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || parts[0] == "" {
		return Money{}, fmt.Errorf("invalid decimal amount")
	}
	whole, err := strconv.ParseUint(parts[0], 10, 63)
	if err != nil || whole > math.MaxInt64 {
		return Money{}, fmt.Errorf("amount out of range")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if fraction == "" || len(fraction) > 9 {
			return Money{}, fmt.Errorf("amount has more than 9 fractional digits")
		}
		for _, r := range fraction {
			if r < '0' || r > '9' {
				return Money{}, fmt.Errorf("invalid decimal amount")
			}
		}
	}
	for len(fraction) < 9 {
		fraction += "0"
	}
	nanos := int64(0)
	if fraction != "" {
		nanos, err = strconv.ParseInt(fraction, 10, 32)
		if err != nil {
			return Money{}, fmt.Errorf("invalid fractional amount")
		}
	}
	// #nosec G115 -- ParseInt used a 32-bit bound for the fractional part.
	m := Money{Units: int64(whole), Nanos: int32(nanos), Currency: strings.ToUpper(strings.TrimSpace(currency))}
	if !m.Valid() {
		return Money{}, fmt.Errorf("invalid currency")
	}
	return m, nil
}

func validCurrency(currency string) bool {
	if len(currency) != 3 {
		return false
	}
	for _, r := range currency {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}
