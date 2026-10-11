package cmd

import (
	"os"
	"path/filepath"
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

// ExitStatus is what main.go applies to the error Execute returns: a usage or
// invocation mistake is 2, a failed operation 1, an ExitCoder its own code.
func TestExitStatus_UsageErrorsAreTwo(t *testing.T) {
	good := testFixturePath(t, "minimal-v2.json")
	cases := map[string][]string{
		"unknown flag":          {"validate", "--no-such-flag", good},
		"unknown command":       {"merge", good, good},
		"missing required flag": {"events", "derive", "--prev", good},
		"wrong argument count":  {"diff", good},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := executeCommand(args...)
			if err == nil {
				t.Fatalf("expected an error")
			}
			code, report := ExitStatus(err)
			if code != 2 {
				t.Errorf("exit code = %d, want 2 (%v)", code, err)
			}
			if !report {
				t.Errorf("a usage error must still be printed")
			}
		})
	}
}

func TestExitStatus_RunFailuresStayOne(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	good := testFixturePath(t, "minimal-v2.json")
	cases := map[string][]string{
		"validate on a missing file":       {"validate", missing},
		"diff on a missing file":           {"diff", good, missing},
		"diff --exit-code on missing file": {"diff", good, missing, "--exit-code"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := executeCommand(args...)
			if err == nil {
				t.Fatalf("expected an error")
			}
			code, report := ExitStatus(err)
			if code != 1 || !report {
				t.Errorf("got code %d report %v, want 1 and printed (%v)", code, report, err)
			}
		})
	}
}

func TestExitStatus_ExitCodersKeepTheirCode(t *testing.T) {
	good := testFixturePath(t, "minimal-v2.json")
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := executeCommand("validate", good, bad)
	code, report := ExitStatus(err)
	if code != 3 || report {
		t.Errorf("partial bulk: got code %d report %v, want 3 and silent", code, report)
	}
	_, _, err = executeCommand("diff", good, good, "--exit-code")
	if err != nil {
		t.Fatalf("identical documents must exit clean, got %v", err)
	}
}

// Every exit-code error that predates the usage/nothing-to-do codes reported
// through its own output and main printed nothing; adding a report flag must not
// start prefixing them with an Error line.
func TestExitStatus_PreexistingCodesStaySilent(t *testing.T) {
	good := testFixturePath(t, "minimal-v2.json")
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"query with no match":    {"query", good, "--status", "error"},
		"validate on a bad file": {"validate", bad},
		"partial bulk":           {"validate", good, bad},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := executeCommand(args...)
			if err == nil {
				t.Fatalf("expected an error")
			}
			if _, report := ExitStatus(err); report {
				t.Errorf("%s must stay silent; main would print %q", name, err)
			}
		})
	}
}
