package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Unit tests for bulk helpers ---

func TestExpandGlobs_LiteralPaths(t *testing.T) {
	// Literal paths that exist should be returned as-is.
	fixture := testFixturePath(t, "minimal-v2.json")
	result, err := expandGlobs([]string{fixture})
	require.NoError(t, err)
	assert.Equal(t, []string{fixture}, result)
}

func TestExpandGlobs_GlobPattern(t *testing.T) {
	// A glob pattern should expand to matching files.
	tmpDir := t.TempDir()
	for _, name := range []string{"a.json", "b.json", "c.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, name), []byte("{}"), 0o600))
	}
	pattern := filepath.Join(tmpDir, "*.json")
	result, err := expandGlobs([]string{pattern})
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestExpandGlobs_NoMatch(t *testing.T) {
	// A glob pattern that matches nothing should return an error.
	_, err := expandGlobs([]string{"/nonexistent/path/*.json"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no files matched")
}

func TestExpandGlobs_MixedLiteralAndGlob(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "one.json")
	f2 := filepath.Join(tmpDir, "two.json")
	require.NoError(t, os.WriteFile(f1, []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(f2, []byte("{}"), 0o600))

	result, err := expandGlobs([]string{f1, filepath.Join(tmpDir, "two*")})
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Contains(t, result, f1)
	assert.Contains(t, result, f2)
}

func TestExpandGlobs_Deduplication(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "dup.json")
	require.NoError(t, os.WriteFile(f1, []byte("{}"), 0o600))

	// Literal path + glob matching same file: literal is always kept,
	// glob is deduped within glob results only. Both appear.
	result, err := expandGlobs([]string{f1, filepath.Join(tmpDir, "dup*")})
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestExpandGlobs_GlobDeduplication(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "file.json")
	require.NoError(t, os.WriteFile(f1, []byte("{}"), 0o600))

	// Two glob patterns matching the same file — should deduplicate.
	result, err := expandGlobs([]string{filepath.Join(tmpDir, "*.json"), filepath.Join(tmpDir, "file*")})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestBulkResultSummary(t *testing.T) {
	results := []BulkResult{
		{File: "a.json", Success: true},
		{File: "b.json", Success: true},
		{File: "c.json", Success: false, Error: "parse error"},
	}
	passed, failed := bulkSummaryCounts(results)
	assert.Equal(t, 2, passed)
	assert.Equal(t, 1, failed)
}

// --- CLI integration tests for multi-file validate ---

func TestValidateMultiFile_AllPass(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	stdout, _, err := executeCommand("validate", fixture, fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestValidateMultiFile_SomeFail(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	_, _, err := executeCommand("validate", fixture, badFile)
	require.Error(t, err, "should exit non-zero when any file fails")
}

func TestValidateMultiFile_JSONOutput(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	stdout, _, _ := executeCommand("validate", "--json", fixture, badFile)
	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &results))
	assert.Len(t, results, 2)
}

func TestValidateSingleFile_Unchanged(t *testing.T) {
	// Single-file behavior must remain identical (no "Results:" summary).
	fixture := testFixturePath(t, "minimal-v2.json")
	stdout, _, err := executeCommand("validate", fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "valid HDF results file")
	assert.NotContains(t, stdout, "Results:")
}

// --- CLI integration tests for multi-file list ---

func TestListMultiFile(t *testing.T) {
	fixture := writeRichFixture(t)

	stdout, _, err := executeCommand("list", fixture, fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestListMultiFile_JSONOutput(t *testing.T) {
	fixture := writeRichFixture(t)

	stdout, _, err := executeCommand("list", "--json", fixture, fixture)
	require.NoError(t, err)
	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &results))
	assert.Len(t, results, 2)
}

func TestListSingleFile_Unchanged(t *testing.T) {
	fixture := writeRichFixture(t)
	stdout, _, err := executeCommand("list", fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Baselines:")
	assert.NotContains(t, stdout, "Results:")
}

// --- CLI integration tests for multi-file query ---

func TestQueryMultiFile(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	stdout, _, err := executeCommand("query", fixture, fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestQueryMultiFile_JSONOutput(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")

	stdout, _, err := executeCommand("query", "--json", fixture, fixture)
	require.NoError(t, err)
	var results []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(stdout), &results))
	assert.Len(t, results, 2)
}

func TestQuerySingleFile_Unchanged(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	stdout, _, err := executeCommand("query", fixture)
	require.NoError(t, err)
	assert.Contains(t, stdout, "matching requirement")
	assert.NotContains(t, stdout, "Results:")
}

// --- Glob expansion in CLI commands ---

func TestValidateMultiFile_GlobExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	// Create two valid HDF files
	fixture := testFixturePath(t, "minimal-v2.json")
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "scan1.json"), data, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "scan2.json"), data, 0o600))

	pattern := filepath.Join(tmpDir, "*.json")
	stdout, _, err := executeCommand("validate", pattern)
	require.NoError(t, err)
	assert.Contains(t, stdout, "Results: 2/2")
}

func TestValidateMultiFile_ContinuesByDefault(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	// Without --fail-fast, should process all files and show summary.
	stdout, _, err := executeCommand("validate", badFile, fixture)
	require.Error(t, err)
	assert.Contains(t, stdout, "Results: 1/2")
}

func TestValidateMultiFile_AbortsWithFailFast(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0o600))

	// With -F, should abort on the bad file.
	_, _, err := executeCommand("validate", "-F", badFile, fixture)
	require.Error(t, err)
}

// --- Bulk convert tests ---

func TestConvertBulk_MultipleFiles(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	// Copy fixture twice with different names
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	f1 := filepath.Join(tmpDir, "scan1.json")
	f2 := filepath.Join(tmpDir, "scan2.json")
	require.NoError(t, os.WriteFile(f1, data, 0o600))
	require.NoError(t, os.WriteFile(f2, data, 0o600))

	outDir := filepath.Join(tmpDir, "output")
	_, _, err = executeCommand("convert", "--from", "legacyhdf", f1, f2, "-o", outDir)
	require.NoError(t, err)

	// Check output files exist with .hdf.json suffix
	_, err = os.Stat(filepath.Join(outDir, "scan1.hdf.json"))
	require.NoError(t, err, "scan1.hdf.json should exist")
	_, err = os.Stat(filepath.Join(outDir, "scan2.hdf.json"))
	require.NoError(t, err, "scan2.hdf.json should exist")
}

func TestConvertBulk_RequiresOutputDir(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	f1 := filepath.Join(tmpDir, "a.json")
	f2 := filepath.Join(tmpDir, "b.json")
	require.NoError(t, os.WriteFile(f1, data, 0o600))
	require.NoError(t, os.WriteFile(f2, data, 0o600))

	// Without -o, bulk convert should error
	_, _, err = executeCommand("convert", "--from", "legacyhdf", f1, f2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "output-directory")
}

func TestConvertBulk_ContinuesByDefault(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	good := filepath.Join(tmpDir, "good.json")
	bad := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(good, data, 0o600))
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))

	outDir := filepath.Join(tmpDir, "output")
	// Without --fail-fast, should skip bad and convert good
	_, _, err = executeCommand("convert", "--from", "legacyhdf", bad, good, "-o", outDir)
	require.Error(t, err) // still exits non-zero

	// Good file should have been converted
	_, statErr := os.Stat(filepath.Join(outDir, "good.hdf.json"))
	require.NoError(t, statErr, "good.hdf.json should exist without --fail-fast")
}

func TestConvertBulk_AbortsWithFailFast(t *testing.T) {
	fixture := legacyhdfFixturePath(t, "input/minimal.json")
	tmpDir := t.TempDir()
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	good := filepath.Join(tmpDir, "good.json")
	bad := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(good, data, 0o600))
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))

	outDir := filepath.Join(tmpDir, "output")
	// Bad file first, with -F — should abort
	_, _, err = executeCommand("convert", "--from", "legacyhdf", "-F", bad, good, "-o", outDir)
	require.Error(t, err)

	// Good file should NOT have been processed
	_, statErr := os.Stat(filepath.Join(outDir, "good.hdf.json"))
	assert.True(t, os.IsNotExist(statErr), "good.hdf.json should not exist when aborting with --fail-fast")
}

// A gate writes every scan into one output directory with a single command.
// Whether that command happened to match one file or twelve is an accident of
// how many scanners ran, so -o <dir> has to mean the same thing either way —
// otherwise a pipeline breaks the day a scanner family drops to one file.
func TestConvertSingleFile_OutputDirectory(t *testing.T) {
	data, err := os.ReadFile(legacyhdfFixturePath(t, "input/minimal.json"))
	require.NoError(t, err)
	inputPath := filepath.Join(t.TempDir(), "scan.json")
	require.NoError(t, os.WriteFile(inputPath, data, 0o600))

	t.Run("existing directory", func(t *testing.T) {
		outDir := t.TempDir()
		_, _, err := executeCommand("convert", "--from", "legacyhdf", inputPath, "-o", outDir+string(filepath.Separator))
		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(outDir, "scan.hdf.json"))
	})

	t.Run("directory that does not exist yet", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "hdf-scans")
		_, _, err := executeCommand("convert", "--from", "legacyhdf", inputPath, "-o", outDir+string(filepath.Separator))
		require.NoError(t, err)
		assert.FileExists(t, filepath.Join(outDir, "scan.hdf.json"))
	})

	t.Run("a plain path is still a file", func(t *testing.T) {
		outFile := filepath.Join(t.TempDir(), "out.json")
		_, _, err := executeCommand("convert", "--from", "legacyhdf", inputPath, "-o", outFile)
		require.NoError(t, err)
		assert.FileExists(t, outFile)
	})
}

// --- Exit codes ---

// exitCodeOf is the code main.go would exit with for an error that came back
// through the root command.
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	require.Error(t, err)
	code, _ := ExitStatus(err)
	return code
}

// exitCodeFromRun is the same for an error obtained by calling a command's run
// path directly: the root tree marks every RunE error, so the mark is applied
// here by hand.
func exitCodeFromRun(t *testing.T, err error) int {
	t.Helper()
	require.Error(t, err)
	code, _ := ExitStatus(&runError{err: err})
	return code
}

func TestRunBulk_ExitCodes(t *testing.T) {
	files := []string{"a", "b", "c"}
	failOn := func(bad ...string) BulkProcessFn {
		return func(file string) error {
			for _, b := range bad {
				if file == b {
					return errors.New("boom")
				}
			}
			return nil
		}
	}
	run := func(fn BulkProcessFn, opts ...bulkOption) error {
		_, err := captureOutput(func() error { return runBulk(files, "op", "done", fn, opts...) })
		return err
	}

	t.Run("every file succeeding is nil", func(t *testing.T) {
		require.NoError(t, run(failOn()))
	})
	t.Run("mixed outcomes exit 3", func(t *testing.T) {
		assert.Equal(t, 3, exitCodeFromRun(t, run(failOn("b"))))
	})
	t.Run("every file failing exits 1", func(t *testing.T) {
		assert.Equal(t, 1, exitCodeFromRun(t, run(failOn("a", "b", "c"))))
	})
	t.Run("withFailClosed keeps 1 for mixed outcomes", func(t *testing.T) {
		assert.Equal(t, 1, exitCodeFromRun(t, run(failOn("b"), withFailClosed())))
	})
}

// Each runBulk caller inherits the vocabulary with no code of its own: 3 when
// some files succeeded and some failed, 1 when every file failed.
func TestBulkExitCodes_PerCaller(t *testing.T) {
	good := testFixturePath(t, "minimal-v2.json")
	rich := writeRichFixture(t)
	legacy := legacyhdfFixturePath(t, "input/minimal.json")
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	bad2 := filepath.Join(dir, "bad2.json")
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))
	require.NoError(t, os.WriteFile(bad2, []byte("not json"), 0o600))

	cases := []struct {
		name      string
		mixed     []string
		allFailed []string
	}{
		{"validate", []string{"validate", good, good, bad}, []string{"validate", bad, bad2}},
		{"list", []string{"list", rich, bad}, []string{"list", bad, bad2}},
		{"query", []string{"query", good, bad}, []string{"query", bad, bad2}},
		{"convert",
			[]string{"convert", "--from", "legacyhdf", legacy, bad, "-o", filepath.Join(dir, "out-mixed")},
			[]string{"convert", "--from", "legacyhdf", bad, bad2, "-o", filepath.Join(dir, "out-failed")}},
	}
	for _, tc := range cases {
		t.Run(tc.name+" mixed exits 3", func(t *testing.T) {
			_, _, err := executeCommand(tc.mixed...)
			assert.Equal(t, 3, exitCodeOf(t, err))
		})
		t.Run(tc.name+" all failed exits 1", func(t *testing.T) {
			_, _, err := executeCommand(tc.allFailed...)
			assert.Equal(t, 1, exitCodeOf(t, err))
		})
	}
}

// A gate is fail-closed: any verdict that failed is exit 1, never 3, and a
// document that could not be evaluated at all is treated the same way.
func TestValidateThreshold_BulkExitCodesStayFailClosed(t *testing.T) {
	dir := t.TempDir()
	clean := writeResultsAt(t, dir, "clean.json", testResultsNoFailures)
	violating := writeResultsAt(t, dir, "violating.json", testResultsForThreshold)
	unreadable := writeResultsAt(t, dir, "unreadable.json", "not json")
	thr := writeResultsAt(t, dir, "threshold.yaml", "failed:\n  total:\n    max: 0\n")

	t.Run("one passing and one failing verdict exits 1", func(t *testing.T) {
		_, _, err := executeCommand("validate", "threshold", clean, violating, "-T", thr)
		assert.Equal(t, 1, exitCodeOf(t, err))
	})
	t.Run("one passing and one unreadable document exits 1", func(t *testing.T) {
		_, _, err := executeCommand("validate", "threshold", clean, unreadable, "-T", thr)
		assert.Equal(t, 1, exitCodeOf(t, err))
	})
}

// add-component is all-or-nothing: a failed file means nothing was written, so
// the run is never partial and exits 1.
func TestSystemAddComponent_BulkExitCodeIsNeverPartial(t *testing.T) {
	sysFile := createBaseSystem(t)
	sbom := bomFixturePath(t, "cyclonedx-sbom.json")
	bad := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))

	_, _, err := executeCommand("system", "add-component", sbom, bad, "--system", sysFile, "--component-name-prefix", "x-")
	assert.Equal(t, 1, exitCodeOf(t, err))
	require.Len(t, readSystemComponents(t, sysFile), 1, "a failed batch must write nothing")
}

func TestFetchGitlabVulnerabilities_GroupExitCodes(t *testing.T) {
	t.Setenv("GITLAB_TOKEN", "tok")

	t.Run("two fetched and two failed exits 3", func(t *testing.T) {
		srv := gvServer(t)
		defer srv.Close()
		var err error
		_ = captureStderr(t, func() {
			_, err = runFetchGV(t, "--url", srv.URL, "--group", "security-demo", "--out-dir", filepath.Join(t.TempDir(), "hdf"))
		})
		assert.Equal(t, 3, exitCodeFromRun(t, err))
	})
	t.Run("every project failing exits 1", func(t *testing.T) {
		// A listing naming only the two projects whose probes are recorded as failures.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Query     string         `json:"query"`
				Variables map[string]any `json:"variables"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			name := strings.TrimPrefix(req.Variables["fullPath"].(string), "security-demo/")
			if strings.Contains(req.Query, "query GroupProjects") {
				_, _ = w.Write([]byte(`{"data":{"group":{"fullPath":"security-demo","projects":{"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[{"fullPath":"security-demo/unscanned-app","archived":false},{"fullPath":"security-demo/empty-app","archived":false}]}}}}`))
				return
			}
			_, _ = w.Write(gvTestdata(t, "probe-"+name+".json"))
		}))
		defer srv.Close()
		var err error
		_ = captureStderr(t, func() {
			_, err = runFetchGV(t, "--url", srv.URL, "--group", "security-demo", "--out-dir", filepath.Join(t.TempDir(), "hdf"))
		})
		assert.Equal(t, 1, exitCodeFromRun(t, err))
	})
}

// A glob that matches nothing is a mistake in every reading, so it is neither a
// success nor a failed run: exit 4, naming the pattern, and the message is printed.
func TestExitStatus_NothingToDoIsFour(t *testing.T) {
	pattern := filepath.Join(t.TempDir(), "*.json")
	for _, args := range [][]string{
		{"validate", pattern},
		{"list", pattern},
		{"convert", pattern, "-o", t.TempDir() + "/"},
	} {
		t.Run(args[0], func(t *testing.T) {
			_, _, err := executeCommand(args...)
			require.Error(t, err)
			code, report := ExitStatus(err)
			assert.Equal(t, 4, code)
			assert.True(t, report, "the message must be printed")
			assert.Contains(t, err.Error(), pattern)
		})
	}
	t.Run("evidence build with no results files", func(t *testing.T) {
		sys := filepath.Join("testdata", "evidence-verify", "system.json")
		_, _, err := executeCommand("evidence", "build", "--system", sys)
		require.Error(t, err)
		code, _ := ExitStatus(err)
		assert.Equal(t, 4, code)
	})
}
