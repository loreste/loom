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
