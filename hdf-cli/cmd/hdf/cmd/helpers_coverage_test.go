package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// SchemaStatusToDisplay (root.go) — cover all branches including default
// ---------------------------------------------------------------------------

func TestSchemaStatusToDisplay(t *testing.T) {
	tests := []struct {
		name   string
		status hdf.ResultStatus
		want   string
	}{
		{"passed", hdf.Passed, StatusPassed},
		{"failed", hdf.Failed, StatusFailed},
		{"error", hdf.Error, StatusError},
		{"notApplicable", hdf.NotApplicable, StatusNotApplicable},
		{"notReviewed", hdf.NotReviewed, StatusNotReviewed},
		{"unknown value falls to default", hdf.ResultStatus("bogus"), StatusNotReviewed},
		{"empty string falls to default", hdf.ResultStatus(""), StatusNotReviewed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SchemaStatusToDisplay(tt.status)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// sanitizeOutput (sanitize.go)
// ---------------------------------------------------------------------------

func TestSanitizeOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text", "hello world", "hello world"},
		{"preserves newline", "line1\nline2", "line1\nline2"},
		{"preserves tab", "col1\tcol2", "col1\tcol2"},
		{"preserves carriage return", "line\r\n", "line\r\n"},
		{"strips ANSI CSI bold", "\x1b[1mBold\x1b[0m", "Bold"},
		{"strips ANSI CSI color", "\x1b[31mred\x1b[0m", "red"},
		{"strips ANSI OSC", "\x1b]0;title\x07rest", "rest"},
		{"replaces NUL", "ab\x00cd", "ab\uFFFDcd"},
		{"replaces BEL alone", "ab\x07cd", "ab\uFFFDcd"},
		{"replaces SOH", "\x01data", "\uFFFDdata"},
		{"empty string", "", ""},
		{"combined ANSI + control char", "\x1b[32m\x01text\x1b[0m", "\uFFFDtext"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeOutput(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// safematch.go — compileSafeRegex, matchString, safeGlobMatch
// ---------------------------------------------------------------------------

func TestSafeMatch_CompileSafeRegex_TooLong(t *testing.T) {
	// Pattern exceeding maxPatternLength should return nil
	longPattern := strings.Repeat("a", maxPatternLength+1)
	sr := compileSafeRegex(longPattern)
	assert.Nil(t, sr, "expected nil for pattern exceeding max length")
}

func TestSafeMatch_CompileSafeRegex_InvalidPattern(t *testing.T) {
	// Unmatched group should fail to compile
	sr := compileSafeRegex("(unclosed")
	assert.Nil(t, sr, "expected nil for invalid regex pattern")
}

func TestSafeMatch_MatchString_NilReceiver(t *testing.T) {
	var sr *safeRegex
	assert.False(t, sr.matchString("anything"), "nil receiver should return false")
}

func TestSafeMatch_MatchString_NilInner(t *testing.T) {
	sr := &safeRegex{re: nil}
	assert.False(t, sr.matchString("anything"), "nil inner regex should return false")
}

func TestSafeMatch_MatchString_ValidMatch(t *testing.T) {
	sr := compileSafeRegex("^hello$")
	require.NotNil(t, sr)
	assert.True(t, sr.matchString("hello"))
	assert.True(t, sr.matchString("HELLO"), "should be case insensitive")
	assert.False(t, sr.matchString("world"))
}

func TestSafeGlobMatch_TooLongPattern(t *testing.T) {
	longPattern := strings.Repeat("x", maxPatternLength+1)
	assert.False(t, safeGlobMatch("test", longPattern))
}

func TestSafeGlobMatch_NormalPatterns(t *testing.T) {
	assert.True(t, safeGlobMatch("AC-2", "AC-*"))
	assert.True(t, safeGlobMatch("hello", "hello"))
	assert.False(t, safeGlobMatch("hello", "world"))
}

// ---------------------------------------------------------------------------
// parseImpactFilter (query.go) — cover invalid value branches
// ---------------------------------------------------------------------------

func TestParseImpactFilter_InvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		wantOp string
		wantV  float64
	}{
		{"invalid operator value", ">abc", "=", 0},
		{"bare invalid", "notanumber", "=", 0},
		{"empty string", "", "=", 0},
		{"spaces only", "   ", "=", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, val := parseImpactFilter(tt.filter)
			assert.Equal(t, tt.wantOp, op)
			assert.Equal(t, tt.wantV, val)
		})
	}
}

// ---------------------------------------------------------------------------
// compareImpact (query.go) — cover default branch (unknown operator)
// ---------------------------------------------------------------------------

func TestCompareImpact_UnknownOperator(t *testing.T) {
	assert.False(t, compareImpact(0.5, "~", 0.5), "unknown operator should return false")
	assert.False(t, compareImpact(0.5, "!=", 0.5), "!= not supported, should return false")
	assert.False(t, compareImpact(0.5, "", 0.5), "empty operator should return false")
}

// ---------------------------------------------------------------------------
// tagMatchesGlob (query.go) — cover nil tags, missing key, []string branch
// ---------------------------------------------------------------------------

func TestTagMatchesGlob_NilTags(t *testing.T) {
	assert.False(t, tagMatchesGlob(nil, "key", "val"))
}

func TestTagMatchesGlob_MissingKey(t *testing.T) {
	tags := map[string]any{"other": "val"}
	assert.False(t, tagMatchesGlob(tags, "key", "val"))
}

func TestTagMatchesGlob_StringSlice(t *testing.T) {
	tags := map[string]any{"nist": []string{"AC-2", "CM-6"}}
	assert.True(t, tagMatchesGlob(tags, "nist", "AC-*"))
	assert.True(t, tagMatchesGlob(tags, "nist", "CM-6"))
	assert.False(t, tagMatchesGlob(tags, "nist", "AU-*"))
}

func TestTagMatchesGlob_AnySliceNoMatch(t *testing.T) {
	tags := map[string]any{"nist": []any{"AC-2", "CM-6"}}
	assert.False(t, tagMatchesGlob(tags, "nist", "AU-*"))
}

func TestTagMatchesGlob_NonStringType(t *testing.T) {
	// Tag value that is neither string nor slice — should return false
	tags := map[string]any{"count": 42}
	assert.False(t, tagMatchesGlob(tags, "count", "42"))
}

// ---------------------------------------------------------------------------
// buildFilters (query.go) — cover tag filter with no colon, STIG ID, CCI, NIST
// ---------------------------------------------------------------------------

func TestBuildFilters_TagNoColon(t *testing.T) {
	// A --tag value without a colon should NOT produce a filter
	old := queryTag
	defer func() { queryTag = old }()
	queryTag = "noColonHere"
	resetQueryFlags()
	queryTag = "noColonHere"

	filters := buildFilters()
	assert.Empty(t, filters, "tag with no colon should not add a filter")
}

func TestBuildFilters_AllFilters(t *testing.T) {
	resetQueryFlags()
	queryStatus = StatusFailed
	querySeverity = "high"
	queryImpact = ">0.5"
	queryCCI = "CCI-000366"
	queryNIST = "AC-*"
	querySTIGID = "V-230221"
	queryTag = "severity:high"
	querySearch = "password"
	defer resetQueryFlags()

	filters := buildFilters()
	// Should have 8 filters (status, severity, impact, cci, nist, stig, tag, search)
	assert.Len(t, filters, 8)
}

// ---------------------------------------------------------------------------
// readFromFile (input.go) — cover file-too-large and permission error branches
// ---------------------------------------------------------------------------

func TestReadFromFile_ExceedsSizeLimit(t *testing.T) {
	// Set maxSizeMB to 0 so getMaxFileSize returns default 50MB;
	// instead set it to 1 byte by using a tiny custom value
	oldMax := maxSizeMB
	maxSizeMB = 1 // 1 MB
	defer func() { maxSizeMB = oldMax }()

	// Create a file larger than 1 MB
	tmpDir := t.TempDir()
	bigFile := filepath.Join(tmpDir, "big.json")
	data := make([]byte, 1*1024*1024+1) // 1 MB + 1 byte
	for i := range data {
		data[i] = 'x'
	}
	require.NoError(t, os.WriteFile(bigFile, data, 0o600))

	_, err := readFromFile(bigFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file too large")
}

func TestReadFromFile_PermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping permission test on Windows (NTFS ACLs ignore Unix mode bits)")
	}
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}
	tmpDir := t.TempDir()
	noReadFile := filepath.Join(tmpDir, "noperm.json")
	require.NoError(t, os.WriteFile(noReadFile, []byte(`{}`), 0o000))

	_, err := readFromFile(noReadFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

func TestReadFromFile_NotRegularFile(t *testing.T) {
	// A directory is caught earlier ("is a directory"), but we can test that path.
	// For a non-regular file we'd need a device file; that's platform-specific.
	// Instead, test the directory branch explicitly.
	tmpDir := t.TempDir()
	_, err := readFromFile(tmpDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is a directory")
}

func TestReadFromFile_SymlinkRejected(t *testing.T) {
	tmpDir := t.TempDir()
	realFile := filepath.Join(tmpDir, "real.json")
	require.NoError(t, os.WriteFile(realFile, []byte(`{"test":true}`), 0o600))
	link := filepath.Join(tmpDir, "link.json")
	require.NoError(t, os.Symlink(realFile, link))

	oldFlag := noFollowSymlinks
	noFollowSymlinks = true
	defer func() { noFollowSymlinks = oldFlag }()

	_, err := readFromFile(link)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to follow symlink")
}

func TestReadFromFile_SymlinkNonexistent(t *testing.T) {
	// noFollowSymlinks with a path that doesn't exist at all
	oldFlag := noFollowSymlinks
	noFollowSymlinks = true
	defer func() { noFollowSymlinks = oldFlag }()

	_, err := readFromFile("/nonexistent/does-not-exist.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
}

// ---------------------------------------------------------------------------
// readFromStdin (input.go) — cover via executeCommand with "-"
// ---------------------------------------------------------------------------

func TestReadFromStdin_EmptyStdin(t *testing.T) {
	// Pipe empty data to stdin
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	_ = w.Close() // close write end immediately → empty read
	defer func() { os.Stdin = oldStdin }()

	_, readErr := readFromStdin()
	require.Error(t, readErr)
	assert.Contains(t, readErr.Error(), "no input provided")
}

func TestReadFromStdin_TooLarge(t *testing.T) {
	oldMax := maxSizeMB
	maxSizeMB = 1 // 1 MB limit
	defer func() { maxSizeMB = oldMax }()

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Write more than 1 MB in a goroutine to avoid blocking
	go func() {
		bigData := make([]byte, 1*1024*1024+100)
		for i := range bigData {
			bigData[i] = 'a'
		}
		_, _ = w.Write(bigData)
		_ = w.Close()
	}()

	_, readErr := readFromStdin()
	require.Error(t, readErr)
	assert.Contains(t, readErr.Error(), "input too large")
}

func TestReadFromStdin_ValidData(t *testing.T) {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	go func() {
		_, _ = w.Write([]byte(`{"valid": "json"}`))
		_ = w.Close()
	}()

	data, readErr := readFromStdin()
	require.NoError(t, readErr)
	assert.Equal(t, `{"valid": "json"}`, string(data))
}

// ---------------------------------------------------------------------------
// parseHDFBaseline (input.go) — cover valid baseline and trailing garbage
// ---------------------------------------------------------------------------

func TestParseHDFBaseline_ValidBaseline(t *testing.T) {
	baseline := buildBaselineFixtureJSON(t)
	result, err := parseHDFBaseline(baseline)
	require.NoError(t, err)
	assert.Equal(t, "test-baseline", result.Name)
	assert.Len(t, result.Requirements, 1)
}

func TestParseHDFBaseline_TrailingGarbage(t *testing.T) {
	baseline := buildBaselineFixtureJSON(t)
	// Append garbage after valid JSON
	withGarbage := make([]byte, len(baseline)+len(`  "extra"`))
	copy(withGarbage, baseline)
	copy(withGarbage[len(baseline):], `  "extra"`)
	_, err := parseHDFBaseline(withGarbage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected data after end of object")
}

func TestParseHDFBaseline_SchemaInvalid(t *testing.T) {
	// Missing required 'name' field
	data := []byte(`{"requirements": []}`)
	_, err := parseHDFBaseline(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation failed")
}

// ---------------------------------------------------------------------------
// parseHDFResults (input.go) — trailing garbage (schema-valid first)
// ---------------------------------------------------------------------------

func TestParseHDFResults_SchemaValidThenTrailingGarbage(t *testing.T) {
	resultsJSON := buildResultsFixtureJSON(t)
	withGarbage := make([]byte, len(resultsJSON)+len(` null`))
	copy(withGarbage, resultsJSON)
	copy(withGarbage[len(resultsJSON):], ` null`)
	_, err := parseHDFResults(withGarbage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected data after end of object")
}

// ---------------------------------------------------------------------------
// runValidate (validate.go) — baseline type, unknown type, JSON output on error
// ---------------------------------------------------------------------------

func TestValidateCommand_BaselineType(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")
	require.NoError(t, os.WriteFile(baselinePath, buildBaselineFixtureJSON(t), 0o600))

	stdout, _, err := executeCommand("validate", "--type", "baseline", baselinePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "valid HDF baseline file")
}

func TestValidateCommand_UnknownType(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.json")
	require.NoError(t, os.WriteFile(path, []byte(`{}`), 0o600))

	_, stderr, err := executeCommand("validate", "--type", "bogus", path)
	require.Error(t, err)
	assert.Contains(t, stderr, "Unknown schema type")
}

func TestValidateCommand_InvalidFile_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"not": "valid"}`), 0o600))

	stdout, _, err := executeCommand("validate", "--json", "--type", "results", path)
	require.Error(t, err)
	assert.Contains(t, stdout, `"valid": false`)
}

func TestValidateCommand_QuietMode(t *testing.T) {
	fixture := testFixturePath(t, "minimal-v2.json")
	stdout, _, err := executeCommand("validate", "--quiet", fixture)
	require.NoError(t, err)
	// Quiet mode should suppress success output
	assert.Empty(t, strings.TrimSpace(stdout))
}

func TestValidateCommand_BaselineAutoDetect(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "auto.json")
	require.NoError(t, os.WriteFile(baselinePath, buildBaselineFixtureJSON(t), 0o600))

	// Without --type flag, should auto-detect as baseline
	stdout, _, err := executeCommand("validate", baselinePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "valid HDF baseline file")
}

// ---------------------------------------------------------------------------
// runQuery (query.go) — cover stdin path, no-args path, no matches text output
// ---------------------------------------------------------------------------

func TestQueryCommand_NoMatches(t *testing.T) {
	reqs := []map[string]any{
		makeRequirement("REQ-001", "Test", 0.7),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--status", "error", fixturePath)
	// Grep convention: exit 1 when no matches found
	require.Error(t, err)
	var exitErr *exitCodeError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, stdout, "No matching requirements found")
}

func TestQueryCommand_NoTitle(t *testing.T) {
	// Build a requirement with no title field
	reqs := []map[string]any{
		{
			"id":           "REQ-NOTITLE",
			"descriptions": []any{map[string]any{"label": "default", "data": "test"}},
			"impact":       0.5,
			"tags":         map[string]any{},
			"results": []any{
				map[string]any{
					"status":    "failed",
					"codeDesc":  "check",
					"startTime": "2025-01-01T00:00:00Z",
				},
			},
		},
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "(no title)")
}

func TestQueryCommand_LimitRespected(t *testing.T) {
	reqs := []map[string]any{
		makeRequirement("REQ-001", "First", 0.7),
		makeRequirement("REQ-002", "Second", 0.5),
		makeRequirement("REQ-003", "Third", 0.3),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--limit", "1", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "REQ-001")
	assert.NotContains(t, stdout, "REQ-003")
}

func TestQueryCommand_STIGIDFilter(t *testing.T) {
	reqs := []map[string]any{
		{
			"id":           "V-230221",
			"title":        "STIG control",
			"descriptions": []any{map[string]any{"label": "default", "data": "test"}},
			"impact":       0.7,
			"tags":         map[string]any{"stig_id": "V-230221"},
			"results": []any{
				map[string]any{
					"status":    "failed",
					"codeDesc":  "check",
					"startTime": "2025-01-01T00:00:00Z",
				},
			},
		},
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--id", "V-230221", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "V-230221")
}

func TestQueryCommand_CCIFilter(t *testing.T) {
	reqs := []map[string]any{
		{
			"id":           "REQ-CCI",
			"title":        "CCI control",
			"descriptions": []any{map[string]any{"label": "default", "data": "test"}},
			"impact":       0.7,
			"tags":         map[string]any{"cci": []any{"CCI-000366"}},
			"results": []any{
				map[string]any{
					"status":    "failed",
					"codeDesc":  "check",
					"startTime": "2025-01-01T00:00:00Z",
				},
			},
		},
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--cci", "CCI-000366", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "REQ-CCI")
}

func TestQueryCommand_SearchInDescription(t *testing.T) {
	reqs := []map[string]any{
		{
			"id":    "REQ-SEARCH",
			"title": "Unrelated title",
			"descriptions": []any{map[string]any{
				"label": "default",
				"data":  "Ensure password complexity requirements are met",
			}},
			"impact": 0.7,
			"tags":   map[string]any{},
			"results": []any{
				map[string]any{
					"status":    "failed",
					"codeDesc":  "check",
					"startTime": "2025-01-01T00:00:00Z",
				},
			},
		},
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--search", "password complexity", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "REQ-SEARCH")
}

func TestQueryCommand_SearchInID(t *testing.T) {
	reqs := []map[string]any{
		makeRequirement("UNIQUE-ID-XYZ", "Some title", 0.7),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--search", "unique-id", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, "UNIQUE-ID-XYZ")
}

func TestQueryCommand_InvalidFile(t *testing.T) {
	_, _, err := executeCommand("query", "/nonexistent/file.json")
	require.Error(t, err)
}

func TestQueryCommand_InvalidHDF(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"not":"hdf"}`), 0o600))

	_, _, err := executeCommand("query", path)
	require.Error(t, err)
}

func TestQueryCommand_BaselineFilter(t *testing.T) {
	reqs := []map[string]any{
		makeRequirement("REQ-001", "Test", 0.7),
	}
	fixturePath := buildQueryFixture(t, reqs)

	// Should find nothing when filtering for a non-matching baseline name (exit 1)
	stdout, _, err := executeCommand("query", "--baseline", "Nonexistent*", fixturePath)
	require.Error(t, err)
	var exitErr *exitCodeError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, stdout, "No matching requirements found")
}

func TestQueryCommand_CountWithJSON(t *testing.T) {
	reqs := []map[string]any{
		makeRequirement("REQ-001", "Test", 0.7),
	}
	fixturePath := buildQueryFixture(t, reqs)

	stdout, _, err := executeCommand("query", "--json", "--count", fixturePath)
	require.NoError(t, err)
	assert.Contains(t, stdout, `"count":`)
}

// ---------------------------------------------------------------------------
// Helpers — build fixture JSON for baselines and results
// ---------------------------------------------------------------------------

func buildBaselineFixtureJSON(t *testing.T) []byte {
	t.Helper()
	baseline := map[string]any{
		"name": "test-baseline",
		"checksum": map[string]any{
			"algorithm": "sha256",
			"value":     "abc123",
		},
		"depends":  []any{},
		"groups":   []any{},
		"inputs":   []any{},
		"supports": []any{},
		"requirements": []any{
			map[string]any{
				"id":    "REQ-001",
				"title": "Test Requirement",
				"descriptions": []any{
					map[string]any{"label": "default", "data": "A test requirement"},
				},
				"impact": 0.7,
				"refs":   []any{},
				"tags":   map[string]any{},
				"code":   "",
				"sourceLocation": map[string]any{
					"ref":  "controls/test.rb",
					"line": 1,
				},
			},
		},
	}
	data, err := json.Marshal(baseline)
	require.NoError(t, err)
	return data
}

func buildResultsFixtureJSON(t *testing.T) []byte {
	t.Helper()
	results := map[string]any{
		"baselines": []any{
			map[string]any{
				"name":     "test-baseline",
				"checksum": map[string]any{"algorithm": "sha256", "value": "abc"},
				"requirements": []any{
					map[string]any{
						"id":           "REQ-001",
						"title":        "Test Req",
						"descriptions": []any{map[string]any{"label": "default", "data": "desc"}},
						"impact":       0.7,
						"tags":         map[string]any{},
						"results": []any{
							map[string]any{
								"status":    "passed",
								"codeDesc":  "check",
								"startTime": "2025-01-01T00:00:00Z",
							},
						},
					},
				},
			},
		},
		"statistics": map[string]any{},
		"components": []any{},
	}
	data, err := json.Marshal(results)
	require.NoError(t, err)
	return data
}

// resetQueryFlags zeroes out all global query flags.
func resetQueryFlags() {
	queryStatus = ""
	querySeverity = ""
	queryImpact = ""
	queryCCI = ""
	queryNIST = ""
	querySTIGID = ""
	queryTag = ""
	querySearch = ""
	queryProfile = ""
	queryCount = false
	queryLimit = 0
}
