package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// testFixturePath returns the path to a test fixture file.
//
//nolint:unparam // name parameter kept for future test extensibility
func testFixturePath(t *testing.T, name string) string {
	t.Helper()
	// Navigate from cmd/hdf/cmd to hdf-schema/test/fixtures
	path := filepath.Join("..", "..", "..", "..", "hdf-schema", "test", "fixtures", name)
	absPath, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		t.Skipf("fixture not found: %s", absPath)
	}
	return absPath
}

// executeCommand runs a command and returns stdout, stderr, and error.
// It creates a fresh command instance for each test to ensure isolation.
func executeCommand(args ...string) (stdout, stderr string, err error) {
	// Create a fresh root command for this test
	cmd := NewRootCmd()

	// Capture stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	// Drain pipes concurrently to avoid deadlock when command output
	// exceeds the OS pipe buffer (4KB on Windows).
	var bufOut, bufErr bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = bufOut.ReadFrom(rOut)
		_, _ = bufErr.ReadFrom(rErr)
		close(done)
	}()

	// Set args and execute
	cmd.SetArgs(args)
	execErr := cmd.Execute()

	// If there's an error, print it to stderr (matching main.go behavior)
	if execErr != nil {
		_, _ = fmt.Fprintf(wErr, "Error: %v\n", execErr)
	}

	// Close write ends and wait for readers to finish
	_ = wOut.Close()
	_ = wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	<-done

	return bufOut.String(), bufErr.String(), execErr
}

// cliTest defines a test case for CLI commands.
type cliTest struct {
	name        string
	args        []string
	wantErr     bool
	wantContain string // Expected in stdout
	wantErrMsg  string // Expected in stdout or stderr
}

// runCLITests runs a slice of CLI tests with the standard test loop.
func runCLITests(t *testing.T, tests []cliTest) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("command panicked: %v", r)
				}
			}()

			stdout, stderr, err := executeCommand(tt.args...)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				// exitCodeError is expected behavior (e.g. grep-style exit 1 for
				// no matches, diff-style exit 1 for differences). Only real errors
				// should fail the test.
				var exitErr *exitCodeError
				if !errors.As(err, &exitErr) {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if tt.wantContain != "" && !strings.Contains(stdout, tt.wantContain) {
				t.Errorf("stdout = %q, want to contain %q", stdout, tt.wantContain)
			}
			if tt.wantErrMsg != "" && !strings.Contains(stderr, tt.wantErrMsg) && !strings.Contains(stdout, tt.wantErrMsg) {
				t.Errorf("output = %q + %q, want to contain %q", stdout, stderr, tt.wantErrMsg)
			}
		})
	}
}

// runNoPanicTests runs tests that just verify commands don't panic.
func runNoPanicTests(t *testing.T, tests []cliTest) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("command panicked: %v", r)
				}
			}()
			_, _, _ = executeCommand(tt.args...)
		})
	}
}

// TestValidateCommand tests the validate command.
func TestValidateCommand(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "valid file", args: []string{"validate", fixture}, wantContain: "valid HDF results file"},
		{name: "missing file", args: []string{"validate", "nonexistent.json"}, wantErr: true, wantErrMsg: "file not found"},
		{name: "no arguments", args: []string{"validate"}, wantErr: true, wantErrMsg: "no input provided"},
		{name: "with --json flag", args: []string{"validate", "--json", fixture}, wantContain: `"valid": true`},
	})
}

// TestQueryCommand tests the query command.
func TestQueryCommand(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "basic query", args: []string{"query", fixture}, wantContain: "matching requirement"},
		{name: "query with --count", args: []string{"query", "--count", fixture}},
		{name: "query with --status failed", args: []string{"query", "--status", "failed", fixture}},
		{name: "query with --limit", args: []string{"query", "--limit", "5", fixture}},
		{name: "query with --json --count", args: []string{"query", "--json", "--count", fixture}, wantContain: `"count":`},
		{name: "query with invalid --limit", args: []string{"query", "--limit", "abc", fixture}, wantErr: true},
	})
}

// TestListCommand tests the list command.
func TestListCommand(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "list summary", args: []string{"list", fixture}, wantContain: "Baselines:"},
		{name: "list --detail requirements", args: []string{"list", fixture, "--detail", "requirements"}, wantContain: "Requirements:"},
		{name: "list --detail baselines", args: []string{"list", fixture, "--detail", "baselines"}, wantContain: "Baselines:"},
		{name: "list --detail invalid", args: []string{"list", fixture, "--detail", "invalid"}, wantErr: true, wantErrMsg: "unknown detail section"},
		{name: "list no args", args: []string{"list"}, wantErr: true},
	})
}

// TestVersionCommand tests the version command.
func TestVersionCommand(t *testing.T) {
	runCLITests(t, []cliTest{
		{name: "basic version", args: []string{"version"}, wantContain: "hdf version"},
		{name: "version with --json", args: []string{"version", "--json"}, wantContain: `"version":`},
	})
}

// TestGlobalFlags tests global flags work across commands.
func TestGlobalFlags(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "validate with --debug", args: []string{"validate", "--debug", fixture}},
		{name: "validate with --max-size", args: []string{"validate", "--max-size", "100", fixture}, wantContain: "valid"},
		{name: "validate with --max-size 0 uses default", args: []string{"validate", "--max-size", "0", fixture}, wantContain: "valid"},
	})
}

// TestQueryFilters tests all query filter flags.
func TestQueryFilters(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		// Status filters
		{name: "status passed", args: []string{"query", "--status", "passed", fixture}},
		{name: "status failed", args: []string{"query", "--status", "failed", fixture}},
		{name: "status error", args: []string{"query", "--status", "error", fixture}},
		{name: "status not_applicable", args: []string{"query", "--status", "not_applicable", fixture}},
		{name: "status not_reviewed", args: []string{"query", "--status", "not_reviewed", fixture}},
		{name: "status short flag -s", args: []string{"query", "-s", "passed", fixture}},

		// Severity filters
		{name: "severity high", args: []string{"query", "--severity", "high", fixture}},
		{name: "severity medium", args: []string{"query", "--severity", "medium", fixture}},
		{name: "severity low", args: []string{"query", "--severity", "low", fixture}},
		{name: "severity none", args: []string{"query", "--severity", "none", fixture}},

		// Impact filters
		{name: "impact equals", args: []string{"query", "--impact", "0.7", fixture}},
		{name: "impact greater than", args: []string{"query", "--impact", ">0.5", fixture}},
		{name: "impact greater or equal", args: []string{"query", "--impact", ">=0.7", fixture}},
		{name: "impact less than", args: []string{"query", "--impact", "<0.4", fixture}},
		{name: "impact less or equal", args: []string{"query", "--impact", "<=0.5", fixture}},

		// Tag filters
		{name: "tag filter", args: []string{"query", "--tag", "severity:high", fixture}},
		{name: "tag short flag -t", args: []string{"query", "-t", "severity:high", fixture}},

		// Text search
		{name: "search filter", args: []string{"query", "--search", "password", fixture}},
		{name: "search case insensitive", args: []string{"query", "--search", "PASSWORD", fixture}},

		// Baseline filter
		{name: "baseline filter", args: []string{"query", "--baseline", "example", fixture}},
		{name: "baseline short flag -p", args: []string{"query", "-p", "example", fixture}},

		// Count and limit
		{name: "count flag", args: []string{"query", "--count", fixture}},
		{name: "count short flag -c", args: []string{"query", "-c", fixture}},
		{name: "limit flag", args: []string{"query", "--limit", "5", fixture}},
		{name: "limit short flag -l", args: []string{"query", "-l", "5", fixture}},
	})
}

// TestListFilters tests list command with filters and aliases.
func TestListFilters(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "list requirements with status filter", args: []string{"list", fixture, "--detail", "requirements", "--status", "passed"}},
		{name: "list requirements with status short flag", args: []string{"list", fixture, "--detail", "requirements", "-s", "passed"}},
		{name: "list requirements with --all", args: []string{"list", fixture, "--detail", "requirements", "--all"}},
		{name: "list requirements with -a", args: []string{"list", fixture, "--detail", "requirements", "-a"}},
		{name: "list components", args: []string{"list", fixture, "--detail", "components"}},
		// Detail aliases
		{name: "detail requirement (singular)", args: []string{"list", fixture, "--detail", "requirement"}, wantContain: "Requirements:"},
		{name: "detail baseline (singular)", args: []string{"list", fixture, "--detail", "baseline"}, wantContain: "Baselines:"},
		{name: "detail r (short)", args: []string{"list", fixture, "--detail", "r"}, wantContain: "Requirements:"},
		{name: "detail p (short)", args: []string{"list", fixture, "--detail", "p"}, wantContain: "Baselines:"},
		{name: "detail t (short)", args: []string{"list", fixture, "--detail", "t"}},
		// ls alias for list
		{name: "ls alias", args: []string{"ls", fixture}, wantContain: "Baselines:"},
		{name: "ls alias with detail", args: []string{"ls", fixture, "--detail", "requirements"}, wantContain: "Requirements:"},
	})
}

// TestJSONOutput tests JSON output format across commands.
func TestJSONOutput(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "validate --json", args: []string{"validate", "--json", fixture}, wantContain: `"valid":`},
		{name: "list --json summary", args: []string{"list", fixture, "--json"}, wantContain: `"baselines":`},
		{name: "list --json requirements", args: []string{"list", fixture, "--detail", "requirements", "--json"}, wantContain: `"id":`},
		{name: "list --json baselines", args: []string{"list", fixture, "--detail", "baselines", "--json"}, wantContain: `"name":`},
		{name: "list --json targets", args: []string{"list", fixture, "--detail", "components", "--json"}, wantContain: `[`},
		{name: "query --json", args: []string{"query", "--json", fixture}, wantContain: "["},
		{name: "query --json --count", args: []string{"query", "--json", "--count", fixture}, wantContain: `"count":`},
		{name: "version --json", args: []string{"version", "--json"}, wantContain: `"version":`},
	})
}

// TestHelpOutput tests that help is available for all commands.
func TestHelpOutput(t *testing.T) {
	runCLITests(t, []cliTest{
		{name: "root help", args: []string{"--help"}, wantContain: "hdf is a CLI tool"},
		{name: "validate help", args: []string{"validate", "--help"}, wantContain: "Validate"},
		{name: "list help", args: []string{"list", "--help"}, wantContain: "Show a summary"},
		{name: "query help", args: []string{"query", "--help"}, wantContain: "Search"},
		{name: "version help", args: []string{"version", "--help"}, wantContain: "version"},
	})
}

// TestAEdgeCases tests edge cases that should not panic or error.
// NOTE: Prefixed with "A" to run before TestHelpOutput which leaves Cobra in help mode.
func TestAEdgeCases(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "query with empty --search", args: []string{"query", "--search", "", fixture}},
		{name: "query with special chars in --search", args: []string{"query", "--search", "test\"quote", fixture}},
		{name: "query with --limit 0", args: []string{"query", "--limit", "0", fixture}},
		{name: "query with very large --limit", args: []string{"query", "--limit", "999999", fixture}},
		{name: "query with --impact >1.0", args: []string{"query", "--impact", ">1.0", fixture}},
		{name: "query with --impact <0", args: []string{"query", "--impact", "<0", fixture}},
		{name: "query with wildcard --nist", args: []string{"query", "--nist", "*", fixture}},
		{name: "validate directory instead of file", args: []string{"validate", "."}, wantErr: true},
		{name: "query all filters combined", args: []string{"query", "--status", "failed", "--severity", "high", "--impact", ">0.5", "--limit", "10", fixture}},
	})
}

// TestAInvalidInputs tests that invalid inputs are handled gracefully.
// NOTE: Prefixed with "A" to run before TestHelpOutput which leaves Cobra in help mode.
func TestAInvalidInputs(t *testing.T) {
	runCLITests(t, []cliTest{
		{name: "validate nonexistent file", args: []string{"validate", "nonexistent.json"}, wantErr: true, wantErrMsg: "file not found"},
		{name: "query with invalid status", args: []string{"query", "--status", "invalid", testFixturePath(t, "minimal-v2.json")}},
	})
}

// TestSpecialCharacters tests handling of special characters in inputs.
func TestSpecialCharacters(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runNoPanicTests(t, []cliTest{
		{name: "search with space", args: []string{"query", "--search", "test value", fixture}},
		{name: "search with quotes", args: []string{"query", "--search", `test"quote`, fixture}},
		{name: "search with backslash", args: []string{"query", "--search", `test\path`, fixture}},
		{name: "tag with special chars", args: []string{"query", "--tag", "key:val$ue", fixture}},
		{name: "nist with regex chars", args: []string{"query", "--nist", "AC-2.*", fixture}},
		{name: "baseline with space", args: []string{"query", "--baseline", "my baseline", fixture}},
	})
}

// TestNegativeNumbers tests handling of negative numbers in flags.
func TestNegativeNumbers(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runNoPanicTests(t, []cliTest{
		{name: "negative limit", args: []string{"query", "--limit", "-1", fixture}},
		{name: "negative max-size", args: []string{"validate", "--max-size", "-1", fixture}},
		{name: "negative impact", args: []string{"query", "--impact", "-0.5", fixture}},
	})
}

// TestDebugFlag tests the --debug flag.
func TestDebugFlag(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	runCLITests(t, []cliTest{
		{name: "validate --debug", args: []string{"validate", "--debug", fixture}},
		{name: "validate -d", args: []string{"validate", "-d", fixture}},
		{name: "query --debug", args: []string{"query", "--debug", fixture}},
	})
}

// TestSchemaDirFlag tests the --schema-dir flag.
func TestSchemaDirFlag(t *testing.T) {
	// validators.schemaDir is package-global; reset on cleanup so later
	// tests in this package use embedded schemas instead of inheriting the
	// disk-loading state set by the CLI's --schema-dir flag.
	t.Cleanup(func() { validators.SetSchemaDir("") })

	fixture := testFixturePath(t, "minimal-v2.json")
	schemaDir := filepath.Join("..", "..", "..", "..", "hdf-schema", "dist", "schemas")

	absSchemaDir, err := filepath.Abs(schemaDir)
	if err != nil {
		t.Skipf("couldn't get absolute schema dir: %v", err)
	}
	if _, err := os.Stat(absSchemaDir); os.IsNotExist(err) {
		t.Skipf("schema dir not found: %s", absSchemaDir)
	}

	runCLITests(t, []cliTest{
		{name: "validate with --schema-dir", args: []string{"validate", "--schema-dir", absSchemaDir, fixture}},
		{name: "query with --schema-dir", args: []string{"query", "--schema-dir", absSchemaDir, fixture}},
	})
}

// TestNoFollowSymlinksFlag tests the --no-follow-symlinks flag.
// NOTE: Uses direct function calls because Cobra's persistent flag state
// doesn't reset properly between executeCommand() calls.
func TestNoFollowSymlinksFlag(t *testing.T) {
	tmpDir := t.TempDir()
	fixture := testFixturePath(t, "minimal-v2.json")
	symlinkPath := filepath.Join(tmpDir, "symlink.json")

	if err := os.Symlink(fixture, symlinkPath); err != nil {
		t.Skipf("couldn't create symlink: %v", err)
	}

	t.Run("follow symlink (default)", func(t *testing.T) {
		noFollowSymlinks = false
		if _, err := readFromFile(symlinkPath); err != nil {
			t.Errorf("unexpected error when following symlink: %v", err)
		}
	})

	t.Run("no-follow-symlinks rejects symlink", func(t *testing.T) {
		noFollowSymlinks = true
		defer func() { noFollowSymlinks = false }()

		_, err := readFromFile(symlinkPath)
		if err == nil {
			t.Error("expected error when refusing to follow symlink, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "refusing to follow symlink") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}
