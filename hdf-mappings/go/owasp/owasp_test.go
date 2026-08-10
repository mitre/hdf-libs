package owasp

import (
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/nist"
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

// See the nikto equivalent: this guard fails when a control in the table stops
// being identical across revisions, signalling the mapping needs real handling.
func TestTableIsRevisionNeutral(t *testing.T) {
	for id, control := range loadOwaspData() {
		for _, c := range strings.Split(control, "|") {
			tr := nist.Translate(strings.TrimSpace(c), 4, 5)
			if tr.Relation != nist.RelationIdentity {
				t.Errorf("owasp %s: control %q is not revision-neutral (relation %s)", id, c, tr.Relation)
			}
		}
	}
}
