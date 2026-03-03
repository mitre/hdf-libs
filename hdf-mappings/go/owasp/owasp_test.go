package owasp

import (
	"testing"
)

func TestNISTControl_KnownIDs(t *testing.T) {
	tests := []struct {
		owaspID  string
		expected string
	}{
		{"A1", "SI-10"},
		{"A2", "SC-23"},
		{"A3", "SI-11"},
		{"A4", "SI-10"},
		{"A5", "AC-3"},
		{"A6", "CM-6"},
		{"A7", "SI-10"},
		{"A8", "SC-23"},
		{"A9", "SI-2"},
		{"A10", "AU-12"},
	}
	for _, tc := range tests {
		t.Run(tc.owaspID, func(t *testing.T) {
			got := NISTControl(tc.owaspID)
			if got != tc.expected {
				t.Errorf("NISTControl(%q) = %q, want %q", tc.owaspID, got, tc.expected)
			}
		})
	}
}

func TestNISTControl_UnknownID(t *testing.T) {
	got := NISTControl("A99")
	if got != "" {
		t.Errorf("NISTControl(%q) = %q, want empty", "A99", got)
	}
}

func TestNISTControl_Empty(t *testing.T) {
	got := NISTControl("")
	if got != "" {
		t.Errorf("NISTControl(%q) = %q, want empty", "", got)
	}
}
