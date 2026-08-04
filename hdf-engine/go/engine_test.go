package hdfengine

import "testing"

func TestVersion(t *testing.T) {
	got := Version()
	if got == "" {
		t.Fatal("Version() returned empty string")
	}
	if got != "3.5.0" {
		t.Errorf("Version() = %q, want %q (workspace lockstep)", got, "3.5.0")
	}
}
