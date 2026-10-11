package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

// groupPaths are the commands that exist only to hold subcommands. Cobra gives
// the root an unknown-command check but not these, because its own check tests
// for a parent, so each one needs the same treatment.
var groupPaths = []string{"evidence", "system", "events", "amend", "fetch", "plan", "label", "generate", "completion"}

func TestRootCmd_UnknownSubcommandOfAGroupIsUsageError(t *testing.T) {
	for _, group := range groupPaths {
		t.Run(group, func(t *testing.T) {
			_, _, err := executeCommand(group, "bogussubcmd")
			if err == nil {
				t.Fatalf("%s bogussubcmd must fail; it exited clean", group)
			}
			if code, _ := ExitStatus(err); code != 2 {
				t.Errorf("exit code = %d, want 2 (%v)", code, err)
			}
			if !strings.Contains(err.Error(), `"bogussubcmd"`) {
				t.Errorf("the error must name the unknown subcommand, got %q", err.Error())
			}
			if !strings.Contains(err.Error(), "hdf "+group) {
				t.Errorf("the error must name the group, got %q", err.Error())
			}
		})
	}
}

// A group invoked bare is how a user discovers it: help, exit 0. Same for
// --help, with or without a trailing token.
func TestRootCmd_GroupWithoutASubcommandStillPrintsHelp(t *testing.T) {
	for _, group := range groupPaths {
		t.Run(group, func(t *testing.T) {
			stdout, _, err := executeCommand(group)
			if err != nil {
				t.Fatalf("%s alone must exit clean, got %v", group, err)
			}
			if !strings.Contains(stdout, "Usage:") {
				t.Errorf("%s alone must print its help, got %q", group, stdout)
			}
			if _, _, err := executeCommand(group, "--help"); err != nil {
				t.Errorf("%s --help must exit clean, got %v", group, err)
			}
			// `hdf <group> help` is a habit Cobra does not serve on its own.
			if _, _, err := executeCommand(group, "help"); err != nil {
				t.Errorf("%s help must exit clean, got %v", group, err)
			}
		})
	}
	if _, _, err := executeCommand(); err != nil {
		t.Errorf("hdf alone must exit clean, got %v", err)
	}
	if _, _, err := executeCommand("--help"); err != nil {
		t.Errorf("hdf --help must exit clean, got %v", err)
	}
}

// A subcommand whose first positional is a file must not have that file read as
// an unknown subcommand name. (`plan info`, not `plan list` — the check caught
// that `plan list` does not exist, which is the point of the card.)
func TestRootCmd_PositionalArgumentsSurviveTheGroupCheck(t *testing.T) {
	good := testFixturePath(t, "minimal-v2.json")
	for _, args := range [][]string{
		{"label", "show", good},
		{"plan", "info", good},
		{"amend", "list", good},
	} {
		t.Run(args[0]+" "+args[1], func(t *testing.T) {
			_, _, err := executeCommand(args...)
			if err == nil {
				return // it ran
			}
			if code, _ := ExitStatus(err); code == 2 {
				t.Errorf("a file positional was read as a usage error: %v", err)
			}
		})
	}
}

// The mechanism, on a synthetic tree: a parent that cannot run rejects a name it
// does not know and still prints help when given nothing.
func TestRejectUnknownSubcommands_Mechanism(t *testing.T) {
	newTree := func() *cobra.Command {
		root := &cobra.Command{Use: "probe", SilenceUsage: true, SilenceErrors: true}
		group := &cobra.Command{Use: "group"}
		group.AddCommand(&cobra.Command{Use: "leaf", Short: "the leaf", RunE: func(*cobra.Command, []string) error { return nil }})
		root.AddCommand(group)
		rejectUnknownSubcommands(root)
		return root
	}

	root := newTree()
	root.SetArgs([]string{"group", "nope"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if err == nil {
		t.Fatal("an unknown subcommand must be an error")
	}
	if want := `unknown command "nope" for "probe group"`; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), want)
	}
	if code, _ := ExitStatus(err); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}

	near := newTree()
	near.SetArgs([]string{"group", "leafx"})
	near.SetOut(io.Discard)
	near.SetErr(io.Discard)
	nearErr := near.Execute()
	if nearErr == nil {
		t.Fatal("an unknown subcommand must be an error")
	}
	if !strings.Contains(nearErr.Error(), "Did you mean this?") || !strings.Contains(nearErr.Error(), "leaf") {
		t.Errorf("a near miss must suggest the real subcommand, got %q", nearErr.Error())
	}

	delegated := newTree()
	var subHelp bytes.Buffer
	delegated.SetArgs([]string{"group", "help", "leaf"})
	delegated.SetOut(&subHelp)
	delegated.SetErr(&subHelp)
	if err := delegated.Execute(); err != nil {
		t.Errorf("`group help leaf` must exit clean, got %v", err)
	}
	if !strings.Contains(subHelp.String(), "the leaf") {
		t.Errorf("`group help leaf` must print the leaf's help, got %q", subHelp.String())
	}
	// The same help the subcommand prints for itself, not a shortened copy.
	if !strings.Contains(subHelp.String(), "--help") {
		t.Errorf("`group help leaf` must print the leaf's own help flag, got %q", subHelp.String())
	}

	bare := newTree()
	var out bytes.Buffer
	bare.SetArgs([]string{"group"})
	bare.SetOut(&out)
	bare.SetErr(&out)
	if err := bare.Execute(); err != nil {
		t.Errorf("a bare group must exit clean, got %v", err)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Errorf("a bare group must print help, got %q", out.String())
	}

	// The root keeps Cobra's own check rather than the injected one. Both format
	// the same message, so the guard is pinned by the root staying non-runnable:
	// the injected run would make it runnable.
	if newTree().Runnable() {
		t.Error("the root must not take the injected run; it keeps Cobra's own unknown-command check")
	}
	untouched := newTree()
	untouched.SetArgs([]string{"grp"})
	untouched.SetOut(io.Discard)
	untouched.SetErr(io.Discard)
	if err := untouched.Execute(); err == nil || !strings.Contains(err.Error(), `unknown command "grp" for "probe"`) {
		t.Errorf("the root's own unknown-command error must be untouched, got %v", err)
	}
}
