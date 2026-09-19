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
	// Exercise the maxSize<=0 fallback against a lowered configured default, so
	// the test does not allocate a full default-sized (256 MB) buffer.
	t.Cleanup(func() { SetDefaultMaxInputSize(0) })
	SetDefaultMaxInputSize(8)
	if err := ValidateInputSize(make([]byte, 9), 0); err == nil {
		t.Fatal("expected error for input exceeding the (configured) default limit")
	}
}

func TestConfiguredDefaultMaxInputSize(t *testing.T) {
	t.Cleanup(func() { SetDefaultMaxInputSize(0) }) // never leak into other tests
	small := make([]byte, 9)

	// With no override, a 9-byte input is fine at the (256 MB) built-in default.
	if err := ValidateInputSize(small, 0); err != nil {
		t.Fatalf("unexpected error at the built-in default: %v", err)
	}
	// Lower the configured default below the input: the same 0-caller now rejects.
	SetDefaultMaxInputSize(8)
	if err := ValidateInputSize(small, 0); err == nil {
		t.Fatal("expected rejection under the lowered configured default")
	}
	// An explicit larger limit still wins over the configured default.
	if err := ValidateInputSize(small, 100); err != nil {
		t.Fatalf("explicit limit should win over the configured default: %v", err)
	}
	// Reset restores the built-in default (the 9-byte input is fine again).
	SetDefaultMaxInputSize(0)
	if err := ValidateInputSize(small, 0); err != nil {
		t.Fatalf("reset should restore the built-in default: %v", err)
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
