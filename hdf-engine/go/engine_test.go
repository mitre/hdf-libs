package hdfengine

import (
	"encoding/json"
	"os"
	"testing"
)

// TestVersion enforces the workspace lockstep: Version() must equal the version
// declared in hdf-engine/package.json — the single source of truth every package
// in the monorepo bumps together. Asserting against a second hardcoded literal
// would let a workspace bump leave Version() stale-but-passing (the drift this
// card fixes); reading the real package.json means a forgotten bump fails here.
func TestVersion(t *testing.T) {
	got := Version()
	if got == "" {
		t.Fatal("Version() returned empty string")
	}

	b, err := os.ReadFile("../package.json")
	if err != nil {
		t.Fatalf("read workspace package.json (the version source of truth): %v", err)
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		t.Fatalf("parse ../package.json: %v", err)
	}
	if pkg.Version == "" {
		t.Fatal("../package.json has no version field")
	}
	if got != pkg.Version {
		t.Errorf("Version() = %q, but hdf-engine/package.json is %q — workspace lockstep drift; bump Version() in engine.go to match", got, pkg.Version)
	}
}
