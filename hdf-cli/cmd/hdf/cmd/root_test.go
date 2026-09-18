package cmd

import (
	"strings"
	"testing"
)

// TestRootCmd_MergeIsNotACommand pins the withdrawal of `hdf merge` (ADR-0016
// Alternative G, owner decision 2026-09-17): combining several scanners'
// results is an in-memory view the MCP read tools build over sources[], never
// a persisted document — a merged file cannot carry a per-tool threshold gate
// and re-namespaces every requirement id. The command must be unknown to the
// root, not merely hidden.
func TestRootCmd_MergeIsNotACommand(t *testing.T) {
	_, stderr, err := executeCommand("merge", "a.hdf.json", "b.hdf.json", "-o", "c.hdf.json")
	if err == nil {
		t.Fatalf("hdf merge must be an unknown command; it executed (stderr %q)", stderr)
	}
	if !strings.Contains(err.Error(), `unknown command "merge"`) {
		t.Errorf("error must be cobra's unknown-command error, got %q", err.Error())
	}
	for _, c := range NewRootCmd().Commands() {
		if c.Name() == "merge" {
			t.Errorf("root still registers a %q subcommand", c.Name())
		}
	}
}
