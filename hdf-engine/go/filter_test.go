package hdfengine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadQueryFixture reads the shared, schema-valid query fixture. src/query.test.ts
// reads the SAME file and runs the SAME Options cases, so the two Filter
// implementations are held to one cross-language contract.
func loadQueryFixture(t *testing.T) hdf.HDFResults {
	t.Helper()
	// Shared cross-language fixture at hdf-engine/testdata (also read by
	// src/query.test.ts), so both Filter implementations run the same input.
	data, err := os.ReadFile(filepath.Join("..", "testdata", "query-fixture.json"))
	require.NoError(t, err)
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(data, &results))
	return results
}

// testStatusOf is the injected status resolver for the tests: it maps a
// requirement's stored result status to the CLI's display convention. The same
// mapping is used in src/query.test.ts so the status filter is parity-tested.
func testStatusOf(c hdf.EvaluatedRequirement) string {
	if len(c.Results) == 0 {
		return ""
	}
	switch string(c.Results[0].Status) {
	case "passed":
		return "passed"
	case "failed":
		return "failed"
	case "error":
		return "error"
	case "notApplicable":
		return "not_applicable"
	case "notReviewed":
		return "not_reviewed"
	}
	return ""
}

func ids(matches []Match) []string {
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.ID
	}
	sort.Strings(out)
	return out
}

// TestFilter_Concurrent is the first failing test: two goroutines call Filter
// with different Options over the same result set and must each get exactly
// their own selection, proving Filter holds no shared/package-level state.
// Run with -race.
func TestFilter_Concurrent(t *testing.T) {
	results := loadQueryFixture(t)
	var wg sync.WaitGroup
	var failedIDs, highIDs []string
	wg.Add(2)
	go func() {
		defer wg.Done()
		failedIDs = ids(Filter(context.Background(), results, Options{Status: []string{"failed"}, StatusOf: testStatusOf}))
	}()
	go func() {
		defer wg.Done()
		highIDs = ids(Filter(context.Background(), results, Options{Severity: []string{"high"}, StatusOf: testStatusOf}))
	}()
	wg.Wait()
	assert.Equal(t, []string{"SV-230221"}, failedIDs, "status=failed selection")
	assert.Equal(t, []string{"SV-230222"}, highIDs, "severity=high selection")
}

// TestFilter_AllNineFilters is the Go side of the cross-language parity contract:
// src/query.test.ts mirrors this exact case table over the same fixture.
func TestFilter_AllNineFilters(t *testing.T) {
	results := loadQueryFixture(t)
	cases := []struct {
		name string
		opts Options
		want []string
	}{
		{"no filters", Options{}, []string{"SV-100001", "SV-100002", "SV-230221", "SV-230222", "SV-230223"}},
		{"status single", Options{Status: []string{"failed"}}, []string{"SV-230221"}},
		{"status OR", Options{Status: []string{"failed", "passed"}}, []string{"SV-230221", "SV-230222"}},
		{"severity single", Options{Severity: []string{"critical"}}, []string{"SV-230221"}},
		{"severity OR", Options{Severity: []string{"high", "medium"}}, []string{"SV-230222", "SV-230223"}},
		{"impact >=0.7", Options{Impact: ">=0.7"}, []string{"SV-230221", "SV-230222"}},
		{"impact <0.5", Options{Impact: "<0.5"}, []string{"SV-100001", "SV-100002"}},
		{"cci", Options{CCI: []string{"CCI-000366"}}, []string{"SV-230222"}},
		{"nist exact", Options{NIST: []string{"AC-2"}}, []string{"SV-230221"}},
		{"nist glob", Options{NIST: []string{"CM-6*"}}, []string{"SV-230222"}},
		{"id req-id", Options{ID: "SV-230221"}, []string{"SV-230221"}},
		{"id stig_id", Options{ID: "RHEL-09-212010"}, []string{"SV-230222"}},
		{"id gid", Options{ID: "V-230221"}, []string{"SV-230221"}},
		{"tag generic", Options{Tag: []string{"nist:AU-12"}}, []string{"SV-230223"}},
		{"search", Options{Search: "auditing"}, []string{"SV-230222"}},
		{"baseline exact", Options{Baseline: "web-hardening"}, []string{"SV-100001", "SV-100002"}},
		{"baseline glob", Options{Baseline: "RHEL9*"}, []string{"SV-230221", "SV-230222", "SV-230223"}},
		{"AND status+baseline", Options{Status: []string{"passed"}, Baseline: "RHEL9-STIG"}, []string{"SV-230222"}},
		{"limit 2", Options{Limit: 2}, []string{"SV-230221", "SV-230222"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.StatusOf = testStatusOf
			assert.Equal(t, tc.want, ids(Filter(context.Background(), results, tc.opts)))
		})
	}
}

// TestFilter_StatusCaseInsensitive proves the status filter matches regardless
// of the case the injected resolver emits: a resolver returning the canonical
// camelCase schema values (notApplicable/notReviewed) is matched by a lowercase
// or camelCase filter alike. src/query.test.ts mirrors this.
func TestFilter_StatusCaseInsensitive(t *testing.T) {
	results := loadQueryFixture(t)
	// Resolver returns canonical schema (effectiveStatus) values verbatim.
	schemaStatusOf := func(c hdf.EvaluatedRequirement) string {
		if len(c.Results) == 0 {
			return "notReviewed"
		}
		return string(c.Results[0].Status)
	}
	// A camelCase filter and a lowercased filter select the same requirement.
	camel := ids(Filter(context.Background(), results, Options{Status: []string{"notApplicable"}, StatusOf: schemaStatusOf}))
	lower := ids(Filter(context.Background(), results, Options{Status: []string{"notapplicable"}, StatusOf: schemaStatusOf}))
	assert.Equal(t, []string{"SV-230223"}, camel, "camelCase filter must match the canonical notApplicable status")
	assert.Equal(t, camel, lower, "status match must be case-insensitive on both sides")
	// And a canonical failed status matches a lowercase filter.
	assert.Equal(t, []string{"SV-230221"}, ids(Filter(context.Background(), results, Options{Status: []string{"failed"}, StatusOf: schemaStatusOf})))
}

// TestFilter_SeverityHonorsExplicitTag proves Filter uses the explicit STIG
// severity when present (impact 0 would otherwise derive to none), matching
// deriveSeverity / hdf_compliance. src/query.test.ts mirrors this.
func TestFilter_SeverityHonorsExplicitTag(t *testing.T) {
	sev := hdf.SeverityHigh
	results := hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{{Name: "b", Requirements: []hdf.EvaluatedRequirement{
		{ID: "X", Impact: 0.0, Severity: &sev, Descriptions: []hdf.Description{{Label: "default", Data: "x"}}, Results: []hdf.RequirementResult{{Status: hdf.NotReviewed}}},
	}}}}
	// The explicit "high" tag wins over the impact-0 derivation ("none").
	assert.Equal(t, []string{"X"}, ids(Filter(context.Background(), results, Options{Severity: []string{"high"}, StatusOf: testStatusOf})))
	assert.Empty(t, Filter(context.Background(), results, Options{Severity: []string{"none"}, StatusOf: testStatusOf}))
	assert.Equal(t, "high", Filter(context.Background(), results, Options{StatusOf: testStatusOf})[0].Severity)
}

func TestFilter_NilStatusOf(t *testing.T) {
	results := loadQueryFixture(t)
	// With no resolver, status is empty and the status filter selects nothing.
	assert.Empty(t, Filter(context.Background(), results, Options{Status: []string{"failed"}}))
	// Non-status filters still work with a nil resolver.
	assert.Equal(t, []string{"SV-230221"}, ids(Filter(context.Background(), results, Options{Severity: []string{"critical"}})))
}

// TestFilter_HonorsCancellation proves a cancelled context stops the scan: an
// already-cancelled ctx yields no matches even with no filters (which would
// otherwise return every requirement).
func TestFilter_HonorsCancellation(t *testing.T) {
	results := loadQueryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Empty(t, Filter(ctx, results, Options{StatusOf: testStatusOf}),
		"a cancelled context must stop the scan before any requirement is collected")
}

// --- helper unit tests, relocated verbatim from hdf-cli query_test.go ---

func TestParseImpactFilter(t *testing.T) {
	tests := []struct {
		name       string
		filter     string
		expectedOp string
		expectedV  float64
	}{
		{"greater than", ">0.5", ">", 0.5},
		{"greater or equal", ">=0.7", ">=", 0.7},
		{"less than", "<0.4", "<", 0.4},
		{"less or equal", "<=0.3", "<=", 0.3},
		{"equals explicit", "=0.5", "=", 0.5},
		{"equals implicit", "0.5", "=", 0.5},
		{"with spaces", "> 0.5", ">", 0.5},
		{"zero", "0", "=", 0.0},
		{"one", "1.0", "=", 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, val := parseImpactFilter(tt.filter)
			assert.Equal(t, tt.expectedOp, op)
			assert.Equal(t, tt.expectedV, val)
		})
	}
}

func TestCompareImpact(t *testing.T) {
	tests := []struct {
		name     string
		impact   float64
		op       string
		val      float64
		expected bool
	}{
		{"0.7 > 0.5", 0.7, ">", 0.5, true},
		{"0.5 > 0.5", 0.5, ">", 0.5, false},
		{"0.7 >= 0.5", 0.7, ">=", 0.5, true},
		{"0.5 >= 0.5", 0.5, ">=", 0.5, true},
		{"0.3 < 0.5", 0.3, "<", 0.5, true},
		{"0.5 < 0.5", 0.5, "<", 0.5, false},
		{"0.3 <= 0.5", 0.3, "<=", 0.5, true},
		{"0.5 = 0.5", 0.5, "=", 0.5, true},
		{"0.7 = 0.5", 0.7, "=", 0.5, false},
		{"unknown op", 0.5, "~", 0.5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, compareImpact(tt.impact, tt.op, tt.val))
		})
	}
}

func TestTagContains(t *testing.T) {
	tests := []struct {
		name     string
		tags     map[string]any
		key      string
		value    string
		expected bool
	}{
		{"nil tags", nil, "cci", "CCI-000366", false},
		{"missing key", map[string]any{"nist": "AC-2"}, "cci", "CCI-000366", false},
		{"string match", map[string]any{"cci": "CCI-000366"}, "cci", "CCI-000366", true},
		{"string case insensitive", map[string]any{"cci": "cci-000366"}, "cci", "CCI-000366", true},
		{"string no match", map[string]any{"cci": "CCI-000367"}, "cci", "CCI-000366", false},
		{"array match", map[string]any{"cci": []any{"CCI-000365", "CCI-000366"}}, "cci", "CCI-000366", true},
		{"array no match", map[string]any{"cci": []any{"CCI-000365"}}, "cci", "CCI-000366", false},
		{"string-slice match", map[string]any{"nist": []string{"AC-2", "CM-6"}}, "nist", "AC-2", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tagContains(tt.tags, tt.key, tt.value))
		})
	}
}

func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		name     string
		glob     string
		expected string
	}{
		{"simple", "AC-2", "^AC-2$"},
		{"asterisk", "AC-*", "^AC-.*$"},
		{"question mark", "AC-?", "^AC-.$"},
		// Each regex metacharacter is escaped exactly once: '.' → '\.'.
		{"escape dot", "test.json", "^test\\.json$"},
		{"multiple wildcards", "*.test.*", "^.*\\.test\\..*$"},
		{"literal backslash", "a\\b", "^a\\\\b$"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, globToRegex(tt.glob))
		})
	}
}

func TestMatchesGlob(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		pattern  string
		expected bool
	}{
		{"exact match", "AC-2", "AC-2", true},
		{"no match", "AC-2", "AC-3", false},
		{"wildcard match", "AC-2", "AC-*", true},
		{"wildcard prefix", "redhat-enterprise-linux", "redhat*", true},
		{"case insensitive", "AC-2", "ac-2", true},
		{"question mark", "AC-2", "AC-?", true},
		{"complex pattern", "profile-name-v123", "profile-*-v???", true},
		{"exact dotted string", "test.json", "test.json", true},
		{"exact dotted no false match", "testXjson", "test.json", false},
		{"dotted wildcard prefix", "v1.2.3-base", "v1.2*", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, matchesGlob(tt.s, tt.pattern))
		})
	}
}

func TestTagMatchesGlob(t *testing.T) {
	tests := []struct {
		name     string
		tags     map[string]any
		key      string
		pattern  string
		expected bool
	}{
		{"exact in array", map[string]any{"nist": []any{"AC-2", "CM-6"}}, "nist", "AC-2", true},
		{"wildcard in array", map[string]any{"nist": []any{"AC-2", "CM-6"}}, "nist", "AC-*", true},
		{"no match in array", map[string]any{"nist": []any{"AC-2", "CM-6"}}, "nist", "AU-*", false},
		{"string value match", map[string]any{"severity": "high"}, "severity", "high", true},
		{"string value wildcard", map[string]any{"stig_id": "RHEL-07-010010"}, "stig_id", "RHEL-07-*", true},
		{"nil tags", nil, "nist", "AC-2", false},
		{"missing key", map[string]any{"nist": "AC-2"}, "cci", "CCI-*", false},
		{"string-slice value", map[string]any{"nist": []string{"AC-2"}}, "nist", "AC-*", true},
		{"non-string tag value", map[string]any{"count": 42}, "count", "42", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tagMatchesGlob(tt.tags, tt.key, tt.pattern))
		})
	}
}

// --- safematch internals + parse/build edge cases, relocated from the CLI's
// helpers_coverage_test.go when the glob matcher and filter builder moved here. ---

func TestCompileSafeRegex_Edge(t *testing.T) {
	assert.Nil(t, compileSafeRegex(strings.Repeat("a", maxPatternLength+1)), "over-length pattern → nil")
	assert.Nil(t, compileSafeRegex("(unclosed"), "invalid pattern → nil")
	sr := compileSafeRegex("^hello$")
	require.NotNil(t, sr)
	assert.True(t, sr.matchString("hello"))
	assert.True(t, sr.matchString("HELLO"), "case-insensitive")
	assert.False(t, sr.matchString("world"))
}

func TestMatchString_NilSafe(t *testing.T) {
	var sr *safeRegex
	assert.False(t, sr.matchString("anything"), "nil receiver → false")
	assert.False(t, (&safeRegex{re: nil}).matchString("anything"), "nil inner regex → false")
}

func TestSafeGlobMatch_TooLongPattern(t *testing.T) {
	assert.False(t, safeGlobMatch("test", strings.Repeat("x", maxPatternLength+1)))
}

func TestParseImpactFilter_InvalidValues(t *testing.T) {
	// Non-numeric values fall back to ("=", 0) for both operator and bare forms.
	cases := []string{">abc", "<=xyz", "notanumber"}
	for _, c := range cases {
		op, val := parseImpactFilter(c)
		assert.Equal(t, "=", op, c)
		assert.Equal(t, 0.0, val, c)
	}
}

func TestFilter_TagWithoutColon(t *testing.T) {
	// A --tag value with no "key:value" colon yields no tag filter, so nothing is
	// narrowed on that axis (matches the shipped buildFilters behavior).
	results := loadQueryFixture(t)
	all := ids(Filter(context.Background(), results, Options{StatusOf: testStatusOf}))
	got := ids(Filter(context.Background(), results, Options{Tag: []string{"nocolonhere"}, StatusOf: testStatusOf}))
	assert.Equal(t, all, got)
}
