package hdfutil

import (
	"strings"
	"testing"
)

func TestValidateInputSize(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		maxSize int
		wantErr bool
	}{
		{"under limit", []byte("hello"), 100, false},
		{"at limit", []byte("hello"), 5, false},
		{"over limit", []byte("hello"), 4, true},
		{"empty always ok", []byte(""), 1, false},
		{"zero maxSize uses default (small input ok)", []byte("x"), 0, false},
		{"negative maxSize uses default", []byte("x"), -1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateInputSize(c.input, c.maxSize)
			if c.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr && !strings.Contains(err.Error(), "exceeds maximum") {
				t.Errorf("error should mention the limit, got %q", err.Error())
			}
		})
	}
}

func TestValidateInputSize_DefaultLimitEnforced(t *testing.T) {
	// One byte over the default must be rejected when maxSize falls back.
	over := make([]byte, DefaultMaxInputSize+1)
	if err := ValidateInputSize(over, 0); err == nil {
		t.Fatal("expected error for input exceeding the default limit")
	}
}

func TestConfiguredDefaultMaxInputSize(t *testing.T) {
	t.Cleanup(func() { SetDefaultMaxInputSize(0) }) // never leak into other tests
	over := make([]byte, DefaultMaxInputSize+1)

	// Baseline: a 0-caller ("use the default") is rejected at the built-in default.
	if err := ValidateInputSize(over, 0); err == nil {
		t.Fatal("expected rejection at the built-in default before configuring an override")
	}

	// Raise the process default; the same 0-caller now passes without touching it.
	SetDefaultMaxInputSize(DefaultMaxInputSize + 10)
	if err := ValidateInputSize(over, 0); err != nil {
		t.Fatalf("expected the raised configured default to admit the input: %v", err)
	}

	// An explicit smaller limit still wins over the configured default.
	if err := ValidateInputSize(over, 5); err == nil {
		t.Fatal("an explicit maxSize must cap below the configured default")
	}

	// A non-positive value restores the built-in default.
	SetDefaultMaxInputSize(0)
	if err := ValidateInputSize(over, 0); err == nil {
		t.Fatal("resetting the configured default must restore the built-in limit")
	}
}

func TestResolveMaxInputSize(t *testing.T) {
	t.Cleanup(func() { SetDefaultMaxInputSize(0) })
	if got := ResolveMaxInputSize(123); got != 123 {
		t.Errorf("explicit value should win: got %d", got)
	}
	if got := ResolveMaxInputSize(0); got != DefaultMaxInputSize {
		t.Errorf("zero with no override should be the built-in default: got %d", got)
	}
	SetDefaultMaxInputSize(999)
	if got := ResolveMaxInputSize(0); got != 999 {
		t.Errorf("zero should resolve to the configured default: got %d", got)
	}
	if got := ResolveMaxInputSize(50); got != 50 {
		t.Errorf("explicit value should still win over the configured default: got %d", got)
	}
}
