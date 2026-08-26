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
