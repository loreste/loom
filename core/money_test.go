package core_test

import (
	"encoding/json"
	"testing"

	"github.com/loreste/loom/core"
)

func TestParseMoneyUsesExactDecimalArithmetic(t *testing.T) {
	left, err := core.ParseMoney(json.Number("0.1"), "usd")
	if err != nil {
		t.Fatal(err)
	}
	right, err := core.ParseMoney("0.10", "USD")
	if err != nil {
		t.Fatal(err)
	}
	if cmp, err := left.Compare(right); err != nil || cmp != 0 {
		t.Fatalf("decimal values should compare exactly: cmp=%d err=%v", cmp, err)
	}
	if _, err := core.ParseMoney("0.0000000001", "USD"); err == nil {
		t.Fatal("more than nine fractional digits must be rejected")
	}
}

func TestMoneyDeltaKeepsSignedAccountingSeparate(t *testing.T) {
	delta := core.MoneyDelta{Units: -2, Nanos: -500_000_000, Currency: "USD"}
	if !delta.Valid() {
		t.Fatal("signed delta should be valid")
	}
	if (core.Money{Units: -1, Currency: "USD"}).Valid() {
		t.Fatal("payment Money must remain non-negative")
	}
	if (core.MoneyDelta{Units: -2, Nanos: 500_000_000, Currency: "USD"}).Valid() {
		t.Fatal("mixed-sign delta must be rejected")
	}
}

func TestCurrencyAllowListIsExplicit(t *testing.T) {
	if !core.CurrencyAllowed("usd", []string{"USD"}) {
		t.Fatal("case-insensitive currency allow-list should match")
	}
	if core.CurrencyAllowed("AAA", []string{"USD"}) {
		t.Fatal("unlisted syntactically valid currency must be rejected")
	}
}

func TestMoneyRejectsCurrencyMismatch(t *testing.T) {
	usd, err := core.ParseMoney("10", "USD")
	if err != nil {
		t.Fatal(err)
	}
	eur, err := core.ParseMoney("10", "EUR")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := usd.Compare(eur); err == nil {
		t.Fatal("currency mismatch must not be comparable")
	}
}
