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
	"time"

	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
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
	return loadResultsFixture(t, "query-fixture.json")
}

// loadResultsFixture reads a results fixture by NAME so a case table naming the
// fixture it describes is actually followed, rather than documenting a path the
// test hardcodes separately.
func loadResultsFixture(t *testing.T, name string) hdf.HDFResults {
	t.Helper()
	require.NotEmpty(t, name, "the case table must name its fixture")
	data, err := os.ReadFile(filepath.Join("..", "testdata", name))
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
		failedIDs = ids(Filter(context.Background(), results, Options{Status: In("failed"), StatusOf: testStatusOf}))
	}()
	go func() {
		defer wg.Done()
		highIDs = ids(Filter(context.Background(), results, Options{Severity: In("high"), StatusOf: testStatusOf}))
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
		{"status single", Options{Status: In("failed")}, []string{"SV-230221"}},
		// testStatusOf returns the CLI's display vocabulary (not_applicable),
		// while a spec names the schema's (notApplicable). Both sides of the
		// comparison canonicalize, which is what reconciles them; without the
		// actual-side half this selects nothing.
		{"status canonical against a display-vocabulary resolver", Options{Status: In("notApplicable")}, []string{"SV-230223"}},
		{"status OR", Options{Status: In("failed", "passed")}, []string{"SV-230221", "SV-230222"}},
		{"severity single", Options{Severity: In("critical")}, []string{"SV-230221"}},
		{"severity OR", Options{Severity: In("high", "medium")}, []string{"SV-230222", "SV-230223"}},
		{"impact >=0.7", Options{Impact: ">=0.7"}, []string{"SV-230221", "SV-230222"}},
		{"impact <0.5", Options{Impact: "<0.5"}, []string{"SV-100001", "SV-100002"}},
		{"cci", Options{CCI: In("CCI-000366")}, []string{"SV-230222"}},
		{"nist exact", Options{NIST: In("AC-2")}, []string{"SV-230221"}},
		{"nist glob", Options{NIST: In("CM-6*")}, []string{"SV-230222"}},
		{"id req-id", Options{ID: "SV-230221"}, []string{"SV-230221"}},
		{"id stig_id", Options{ID: "RHEL-09-212010"}, []string{"SV-230222"}},
		{"id gid", Options{ID: "V-230221"}, []string{"SV-230221"}},
		{"tag generic", Options{Tag: In("nist:AU-12")}, []string{"SV-230223"}},
		{"search", Options{Search: "auditing"}, []string{"SV-230222"}},
		{"baseline exact", Options{Baseline: "web-hardening"}, []string{"SV-100001", "SV-100002"}},
		{"baseline glob", Options{Baseline: "RHEL9*"}, []string{"SV-230221", "SV-230222", "SV-230223"}},
		{"AND status+baseline", Options{Status: In("passed"), Baseline: "RHEL9-STIG"}, []string{"SV-230222"}},
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
	camel := ids(Filter(context.Background(), results, Options{Status: In("notApplicable"), StatusOf: schemaStatusOf}))
	lower := ids(Filter(context.Background(), results, Options{Status: In("notapplicable"), StatusOf: schemaStatusOf}))
	assert.Equal(t, []string{"SV-230223"}, camel, "camelCase filter must match the canonical notApplicable status")
	assert.Equal(t, camel, lower, "status match must be case-insensitive on both sides")
	// And a canonical failed status matches a lowercase filter.
	assert.Equal(t, []string{"SV-230221"}, ids(Filter(context.Background(), results, Options{Status: In("failed"), StatusOf: schemaStatusOf})))
}

// TestFilter_SeverityHonorsExplicitTag proves Filter uses the explicit STIG
// severity when present (impact 0 would otherwise derive to none), matching
// deriveSeverity / hdf_compliance. src/query.test.ts mirrors this.
func TestFilter_SeverityHonorsExplicitTag(t *testing.T) {
	results := testhdf.Results(testhdf.Req("X", testhdf.Severity("high")))
	// The explicit "high" tag wins over the impact-0 derivation ("none").
	assert.Equal(t, []string{"X"}, ids(Filter(context.Background(), results, Options{Severity: In("high"), StatusOf: testStatusOf})))
	assert.Empty(t, Filter(context.Background(), results, Options{Severity: In("none"), StatusOf: testStatusOf}))
	assert.Equal(t, "high", Filter(context.Background(), results, Options{StatusOf: testStatusOf})[0].Severity)
}

func TestFilter_NilStatusOf(t *testing.T) {
	results := loadQueryFixture(t)
	// With no resolver, status is empty and the status filter selects nothing.
	assert.Empty(t, Filter(context.Background(), results, Options{Status: In("failed")}))
	// Non-status filters still work with a nil resolver.
	assert.Equal(t, []string{"SV-230221"}, ids(Filter(context.Background(), results, Options{Severity: In("critical")})))
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
			op, val, ok := parseImpactFilter(tt.filter)
			assert.True(t, ok, "valid filter must parse")
			assert.Equal(t, tt.expectedOp, op)
			assert.Equal(t, tt.expectedV, val)
		})
	}
}

func TestParseImpactFilter_Malformed(t *testing.T) {
	// A malformed operand must be reported (ok=false), NOT coerced to =0.
	for _, bad := range []string{">x", ">=", "<=abc", "0x1f", "impact", ""} {
		_, _, ok := parseImpactFilter(bad)
		assert.False(t, ok, "%q must be reported invalid, not coerced", bad)
		assert.False(t, ValidImpactFilter(bad), "%q must be invalid", bad)
	}
	assert.True(t, ValidImpactFilter(">0.5"))
	assert.True(t, ValidImpactFilter("0"))
}

// TestParseImpactFilter_StrictDecimalParity locks the impact-filter operand to a
// plain-decimal grammar, kept byte-for-byte in lockstep with the TS engine
// (bead 4908.15). strconv.ParseFloat is more liberal than JS Number(): it also
// accepts underscores (1_000), hex-floats (0x1p-2), and Inf/NaN — none of which
// are a sensible 0.0–1.0 threshold and all of which JS parses differently. Both
// engines reject the identical set so a filter behaves the same in Go and TS.
func TestParseImpactFilter_StrictDecimalParity(t *testing.T) {
	for _, good := range []string{"0.5", ".5", "5.", "+0.5", "-0.5", "1e-2", "1E2", "017", "0", "1", ">=0.7", "<0.5", "  0.5  ", "  >0.5", "> 0.5"} {
		_, _, ok := parseImpactFilter(good)
		assert.True(t, ok, "%q must be accepted", good)
		assert.True(t, ValidImpactFilter(good), "%q must be valid", good)
	}
	for _, bad := range []string{"0x1f", "0X1F", "0b101", "0o17", "1_000", "1_0",
		"0x1p-2", "0x1.8p1", "Inf", "inf", "Infinity", "NaN", "nan", "1e400", ">1_000", ">=Inf"} {
		_, _, ok := parseImpactFilter(bad)
		assert.False(t, ok, "%q must be rejected", bad)
		assert.False(t, ValidImpactFilter(bad), "%q must be invalid", bad)
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
	// Non-numeric operands must be reported invalid (ok=false), NOT coerced to
	// ("=", 0) — a coerced typo returned confidently-wrong impact==0 rows.
	cases := []string{">abc", "<=xyz", "notanumber"}
	for _, c := range cases {
		_, _, ok := parseImpactFilter(c)
		assert.False(t, ok, c)
	}
}

// TestFilter_MalformedImpactMatchesNothing proves the engine no longer silently
// degrades a malformed impact filter to impact==0.
// TestSafeGlobMatch_LengthCaps documents the byte + expanded-regex caps the TS
// peer (src/safematch.ts) is held to for parity: an over-byte glob and a small
// glob that expands past the limit are both rejected.
func TestSafeGlobMatch_LengthCaps(t *testing.T) {
	// Subject == pattern so a MISSING cap would MATCH; the cap makes it false.
	// 200 accented chars = 400 UTF-8 bytes → over the 256 glob byte cap.
	assert.False(t, safeGlobMatch(strings.Repeat("é", 200), strings.Repeat("é", 200)))
	// 200 dots = 200-byte glob but a 402-byte expanded regex → over the cap.
	assert.False(t, safeGlobMatch(strings.Repeat(".", 200), strings.Repeat(".", 200)))
	// A short pattern whose expansion stays under the cap still matches.
	assert.True(t, safeGlobMatch("AC-2", "AC-*"))
}

func TestFilter_MalformedImpactMatchesNothing(t *testing.T) {
	results := loadQueryFixture(t)
	assert.Empty(t, Filter(context.Background(), results, Options{Impact: ">x", StatusOf: testStatusOf}),
		"a malformed impact filter must match nothing, not impact==0 rows")
}

// This previously asserted the OPPOSITE — that a colonless value yields no tag
// filter, returning the whole document — with a comment saying it matched the
// shipped behaviour. It did, and the shipped behaviour was a gate-widening bug:
// a predicate naming no key can never match, so dropping it let a rule bound the
// entire document. Both languages pinned it, each with its own comment calling
// it intended, which is how it survived.
func TestFilter_TagWithoutColon(t *testing.T) {
	results := loadQueryFixture(t)
	all := ids(Filter(context.Background(), results, Options{StatusOf: testStatusOf}))
	require.NotEmpty(t, all, "precondition: the document is non-empty")
	got := ids(Filter(context.Background(), results, Options{Tag: In("nocolonhere"), StatusOf: testStatusOf}))
	assert.Empty(t, got, "a colonless tag selects nothing rather than everything")
}

// TestFilter_MatchCarriesIndices pins the positional identity of a match: every
// Match names the baseline and requirement it came from by index, so a consumer
// can address the source requirement directly instead of re-deriving it from
// (baseline name, id) — a key that is not unique in shipped converter output
// (hdf-libs-js1nv.2). src/query.test.ts asserts the same contract.
func TestFilter_MatchCarriesIndices(t *testing.T) {
	results := loadQueryFixture(t)
	matches := Filter(context.Background(), results, Options{StatusOf: testStatusOf})
	require.Len(t, matches, 5)
	for _, m := range matches {
		require.Less(t, m.BaselineIndex, len(results.Baselines), "baseline index in range for %s", m.ID)
		b := results.Baselines[m.BaselineIndex]
		require.Less(t, m.Index, len(b.Requirements), "requirement index in range for %s", m.ID)
		assert.Equal(t, b.Name, m.Baseline, "baseline name must agree with the indexed baseline")
		assert.Equal(t, b.Requirements[m.Index].ID, m.ID, "indexed requirement must be the matched one")
	}
	// Positions are exact, not merely consistent: the fixture's first baseline
	// (RHEL9-STIG) holds SV-230221..3 at 0..2 and web-hardening holds SV-100001..2.
	byID := map[string]Match{}
	for _, m := range matches {
		byID[m.ID] = m
	}
	assert.Equal(t, Match{ID: "SV-230223", Title: byID["SV-230223"].Title, Status: byID["SV-230223"].Status,
		Impact: byID["SV-230223"].Impact, Severity: byID["SV-230223"].Severity, Baseline: "RHEL9-STIG",
		BaselineIndex: 0, Index: 2}, byID["SV-230223"])
	assert.Equal(t, 1, byID["SV-100002"].BaselineIndex)
	assert.Equal(t, 1, byID["SV-100002"].Index)
}

// TestFilter_IndicesDistinguishRepeatedKeys: on real converter output where one
// baseline name carries many baselines and (name, id) repeats, the indices are
// unique even though the names are not.
func TestFilter_IndicesDistinguishRepeatedKeys(t *testing.T) {
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(fixtures.Results.DuplicateBaselines, &results))
	matches := Filter(context.Background(), results, Options{StatusOf: testStatusOf})
	require.Len(t, matches, 94, "the Prisma fixture holds 94 requirements across 16 baselines")
	seenKey := map[string]int{}
	seenPos := map[[2]int]bool{}
	for _, m := range matches {
		seenKey[m.Baseline+"\x00"+m.ID]++
		pos := [2]int{m.BaselineIndex, m.Index}
		assert.False(t, seenPos[pos], "position %v must be unique", pos)
		seenPos[pos] = true
	}
	assert.Equal(t, 6, seenKey["Prisma Cloud Scan\x0060522-redhat-RHEL7-high"], "the (name,id) key repeats six times in this fixture")
}

// amendmentCases is the shared cross-language contract for the disposition and
// poams filters: test/query.test.ts reads the SAME file and runs the SAME cases,
// so the two implementations cannot drift. The reference clock lives in the file
// too, which is what keeps "expired" a property of the fixture rather than of
// the day the suite runs.
type amendmentCases struct {
	Now               string         `json:"now"`
	DispositionValues []string       `json:"dispositionValues"`
	PoamTypeValues    []string       `json:"poamTypeValues"`
	Fixture           hdf.HDFResults `json:"fixture"`
	Cases             []struct {
		Name    string `json:"name"`
		Options struct {
			Status      []string `json:"status"`
			Disposition Values   `json:"disposition"`
			Poams       string   `json:"poams"`
			PoamType    Values   `json:"poamType"`
			ID          string   `json:"id"`
			Impact      string   `json:"impact"`
			RawImpact   string   `json:"rawImpact"`
		} `json:"options"`
		EffectiveStatus bool     `json:"effectiveStatus"`
		Expect          []string `json:"expect"`
	} `json:"cases"`
}

func loadAmendmentCases(t *testing.T) amendmentCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "amendment-filter-cases.json"))
	require.NoError(t, err)
	var table amendmentCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	return table
}

// The amendments layer is reachable as a filter: disposition names the governing
// override's type, and poams reports whether a remediation plan is still in
// force. Both are resolved through the shared governing-override rule rather
// than from the stored output-cache fields, so a filter and the status it runs
// alongside cannot disagree.
func TestFilterAmendmentVocabulary(t *testing.T) {
	table := loadAmendmentCases(t)
	now, err := time.Parse(time.RFC3339, table.Now)
	require.NoError(t, err)

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			opts := Options{
				Status:      In(tc.Options.Status...),
				Disposition: tc.Options.Disposition,
				Poams:       tc.Options.Poams,
				PoamType:    tc.Options.PoamType,
				ID:          tc.Options.ID,
				Impact:      tc.Options.Impact,
				RawImpact:   tc.Options.RawImpact,
				Now:         now,
				StatusOf:    testStatusOf,
			}
			if tc.EffectiveStatus {
				// A governing waiver has to move a requirement off "failed"
				// before a status filter sees it, or a policy keyed on status
				// blames findings somebody already adjudicated.
				opts.StatusOf = effectiveStatusOf(false)
			}
			assert.ElementsMatch(t, tc.Expect, ids(Filter(context.Background(), table.Fixture, opts)))
		})
	}
}

// Both closed vocabularies are asserted against the SCHEMA ITSELF, not only
// against each other. The shared table keeps Go and TypeScript aligned, but two
// languages can agree on a list that has fallen behind the schema — and then a
// value the schema admits is silently unfilterable, matching nothing on every
// surface with no test failing. Reading the source schema is what makes adding a
// kind break the build. (hdf-libs-g2suj is the same assertion for the remaining
// vocabularies; this closes it for these two.)
func TestAmendmentVocabulariesMatchTheSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "hdf-schema", "src", "schemas", "primitives", "extensions.schema.json"))
	require.NoError(t, err, "the schema source is the authority these lists must track")

	var ext struct {
		Defs struct {
			POAM struct {
				Properties struct {
					Type struct {
						Enum []string `json:"enum"`
					} `json:"type"`
				} `json:"properties"`
			} `json:"POAM"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(data, &ext))
	require.NotEmpty(t, ext.Defs.POAM.Properties.Type.Enum, "an empty enum would pass vacuously")
	assert.ElementsMatch(t, ext.Defs.POAM.Properties.Type.Enum, PoamTypeValues,
		"a POA&M kind the schema admits must be filterable; a fifth would otherwise match nothing everywhere")

	amendments, err := os.ReadFile(filepath.Join("..", "..", "hdf-schema", "src", "schemas", "primitives", "amendments.schema.json"))
	require.NoError(t, err)
	var am struct {
		Defs struct {
			OverrideType struct {
				Enum []string `json:"enum"`
			} `json:"Override_Type"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(amendments, &am))
	require.NotEmpty(t, am.Defs.OverrideType.Enum)
	assert.ElementsMatch(t, am.Defs.OverrideType.Enum, DispositionValues,
		"an override type the schema admits must be filterable")
}

// The two amendment vocabularies are closed, and the shared table is what keeps
// the Go and TypeScript lists from drifting apart or from the schema enum.
func TestAmendmentVocabulariesMatchTheSharedTable(t *testing.T) {
	table := loadAmendmentCases(t)
	require.NotEmpty(t, table.DispositionValues, "an empty list would pass vacuously")
	assert.ElementsMatch(t, table.DispositionValues, DispositionValues)
	for _, value := range table.DispositionValues {
		assert.True(t, ValidDisposition(value), "%q is in the table and must be accepted", value)
	}

	require.NotEmpty(t, table.PoamTypeValues, "an empty list would pass vacuously")
	assert.ElementsMatch(t, table.PoamTypeValues, PoamTypeValues)
	for _, value := range table.PoamTypeValues {
		assert.True(t, ValidPoamType(value), "%q is in the table and must be accepted", value)
	}

	// The two vocabularies must stay DISJOINT. They are separate predicates, and
	// a value in both would make "riskAdjustment" (an override) and
	// "riskAcceptance" (a plan) neighbours in one namespace — one letter apart
	// mid-word, selecting entirely different populations.
	for _, d := range DispositionValues {
		assert.False(t, ValidPoamType(d), "%q is an override type and must not name a plan kind", d)
	}
	for _, k := range PoamTypeValues {
		assert.False(t, ValidDisposition(k), "%q is a plan kind and must not name an override type", k)
	}
}

// A typo must be refused rather than matching nothing: a disposition that names
// no override type can only ever return an empty set, which reads as a clean run
// over a filter the caller believed was applied.
func TestValidDisposition(t *testing.T) {
	for _, ok := range []string{"waiver", "FALSEPOSITIVE", "  riskAdjustment  "} {
		assert.True(t, ValidDisposition(ok), "%q must be accepted", ok)
	}
	for _, bad := range []string{"", "waver", "riskadjustmnet", "suppressed", "none"} {
		assert.False(t, ValidDisposition(bad), "%q must be rejected", bad)
	}
}

// ValidPoamFilter is what a caller uses to reject an unrecognized value up front
// instead of letting it match nothing and report a passing gate.
func TestValidPoamFilter(t *testing.T) {
	for _, ok := range []string{"valid", "none-valid", "  NONE-VALID  "} {
		assert.True(t, ValidPoamFilter(ok), "%q must be accepted", ok)
	}
	for _, bad := range []string{"", "absent", "present", "expired", "none"} {
		assert.False(t, ValidPoamFilter(bad), "%q must be rejected", bad)
	}
}

// A riskAdjustment formally re-scores a finding's impact. The filter compared the
// RAW impact, so an assessor could downgrade a critical and every gate keyed on
// impact behaved as though nothing had happened — the same amendments-blindness
// disposition and POA&M validity closed, in the field nobody looked at. --status
// has resolved overrides all along; impact now does too.
func TestFilterImpactResolvesOverrides(t *testing.T) {
	ref := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(s string) time.Time {
		parsed, err := time.Parse(time.RFC3339, s)
		require.NoError(t, err)
		return parsed
	}
	adjusted := func(id string, raw, to float64, expires string) hdf.EvaluatedRequirement {
		value := to
		return hdf.EvaluatedRequirement{
			ID: id, Impact: raw,
			Results: []hdf.RequirementResult{{Status: "failed"}},
			StatusOverrides: []hdf.StatusOverride{{
				Type: hdf.RiskAdjustment, Reason: "environmental context",
				AppliedAt: at("2024-06-01T00:00:00Z"), ExpiresAt: at(expires),
				Impact: &hdf.ImpactOverride{Value: value},
			}},
		}
	}
	results := hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{{
		Name: "adjustments",
		Requirements: []hdf.EvaluatedRequirement{
			{ID: "RAW-HIGH", Impact: 0.9, Results: []hdf.RequirementResult{{Status: "failed"}}},
			adjusted("ADJUSTED-DOWN", 0.9, 0.3, "2099-12-31T00:00:00Z"),
			adjusted("ADJUSTMENT-LAPSED", 0.9, 0.3, "2020-01-01T00:00:00Z"),
		},
	}}}

	assert.Equal(t, []string{"ADJUSTMENT-LAPSED", "RAW-HIGH"},
		ids(Filter(context.Background(), results, Options{Impact: ">=0.7", Now: ref, StatusOf: testStatusOf})),
		"a governing adjustment takes the requirement out of the high band; a lapsed one does not")

	assert.Equal(t, []string{"ADJUSTED-DOWN"},
		ids(Filter(context.Background(), results, Options{Impact: "<0.5", Now: ref, StatusOf: testStatusOf})),
		"and puts it in the band it was re-scored into")

	// The row must agree with the filter that selected it and with its own
	// severity column. Status has no raw twin on a Match either — the display
	// status is the effective one — so impact follows the same precedent.
	rows := Filter(context.Background(), results, Options{ID: "ADJUSTED-DOWN", Now: ref, StatusOf: testStatusOf})
	require.Len(t, rows, 1)
	assert.InDelta(t, 0.3, rows[0].Impact, 1e-9,
		"the row reports the impact the requirement was re-scored to, not the one it left")
	assert.Equal(t, "low", rows[0].Severity,
		"so the impact and severity columns cannot contradict each other")
}

// vulnerabilityCases is the shared cross-language contract for the cvss, epss,
// kev and cwe filters. test/query.test.ts reads the SAME file and runs the SAME
// cases, so the two implementations are held to one contract rather than two
// hand-kept copies. The decisions each case pins are recorded in the file's
// own $comment.
type vulnerabilityCases struct {
	Fixture hdf.HDFResults `json:"fixture"`
	Cases   []struct {
		Name    string `json:"name"`
		Options struct {
			Cvss string   `json:"cvss"`
			Epss string   `json:"epss"`
			Kev  string   `json:"kev"`
			Cwe  []string `json:"cwe"`
		} `json:"options"`
		Expect []string `json:"expect"`
	} `json:"cases"`
}

func TestFilterVulnerabilityFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "vulnerability-filter-cases.json"))
	require.NoError(t, err)
	var table vulnerabilityCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			assert.ElementsMatch(t, tc.Expect, ids(Filter(context.Background(), table.Fixture, Options{
				Cvss: tc.Options.Cvss, Epss: tc.Options.Epss, Kev: tc.Options.Kev, Cwe: In(tc.Options.Cwe...),
				StatusOf: testStatusOf,
			})))
		})
	}
}

// A baseline's labels say which system, component or environment it covers, and
// nothing could ask about them — so "no failures in anything labelled
// environment=production" was a policy that could not be written.
//
// The predicate is BASELINE-level, checked once per baseline beside the existing
// name filter rather than per requirement, because a label is a property of the
// baseline and not of any requirement in it.
type baselineLabelCases struct {
	FixtureFile           string   `json:"fixtureFile"`
	UnfilteredCount       int      `json:"unfilteredCount"`
	UnlabelledBaselineIDs []string `json:"unlabelledBaselineIDs"`
	Cases                 []struct {
		Name   string   `json:"name"`
		Labels []string `json:"labels"`
		Expect []string `json:"expect"`
	} `json:"cases"`
	Validity []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"validity"`
}

func loadBaselineLabelCases(t *testing.T) baselineLabelCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "baseline-label-filter-cases.json"))
	require.NoError(t, err)
	var table baselineLabelCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	require.NotEmpty(t, table.Validity)
	return table
}

func TestFilterByBaselineLabel(t *testing.T) {
	table := loadBaselineLabelCases(t)
	results := loadResultsFixture(t, table.FixtureFile)

	require.Len(t, ids(Filter(context.Background(), results, Options{StatusOf: testStatusOf})),
		table.UnfilteredCount, "the table describes a different fixture than the one loaded")

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := ids(Filter(context.Background(), results, Options{
				BaselineLabel: In(tc.Labels...),
				StatusOf:      testStatusOf,
			}))
			if len(tc.Expect) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.Expect, got)
		})
	}
}

// A colonless value names no key, so it can never match any document. Selecting
// nothing and being ignored are the same forever-green gate under a max bound,
// which is why the CLI refuses one rather than relying on the filter's silence.
type tagCases struct {
	FixtureFile     string `json:"fixtureFile"`
	UnfilteredCount int    `json:"unfilteredCount"`
	Cases           []struct {
		Name   string   `json:"name"`
		Tags   []string `json:"tags"`
		Expect []string `json:"expect"`
	} `json:"cases"`
	Validity []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"validity"`
}

func loadTagCases(t *testing.T) tagCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "tag-filter-cases.json"))
	require.NoError(t, err)
	var table tagCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	require.NotEmpty(t, table.Validity)
	return table
}

// A colonless tag predicate used to be DROPPED rather than applied: the filter
// list was built only from predicates carrying a colon, so when every predicate
// was colonless nothing was appended and the gate matched the whole document —
// widening what a rule bounded instead of narrowing it.
func TestFilterByTag(t *testing.T) {
	table := loadTagCases(t)
	results := loadResultsFixture(t, table.FixtureFile)

	require.Len(t, ids(Filter(context.Background(), results, Options{StatusOf: testStatusOf})),
		table.UnfilteredCount, "the table describes a different fixture than the one loaded")

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := ids(Filter(context.Background(), results, Options{
				Tag:      In(tc.Tags...),
				StatusOf: testStatusOf,
			}))
			if len(tc.Expect) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.Expect, got)
		})
	}
}

// idCases is the shared id-filter table. Its fixture is the REAL Grype scan from
// @mitre/hdf-fixtures rather than ../testdata, because the defect it pins exists
// only on real converter output: the CVE a user knows is not the id the document
// carries.
type idCases struct {
	FixtureFile     string `json:"fixtureFile"`
	UnfilteredCount int    `json:"unfilteredCount"`
	Cases           []struct {
		Name   string   `json:"name"`
		ID     string   `json:"id"`
		Expect []string `json:"expect"`
	} `json:"cases"`
}

func loadIDCases(t *testing.T) idCases {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "id-filter-cases.json"))
	require.NoError(t, err)
	var table idCases
	require.NoError(t, json.Unmarshal(data, &table))
	require.NotEmpty(t, table.Cases, "an empty table would pass vacuously")
	require.Equal(t, "merge-grype.json", table.FixtureFile,
		"this loader reads the shared fixture by name; the table must say which one it describes")
	return table
}

// Parity: test/query.test.ts reads the same table and runs the same cases.
//
// The negative cases carry the weight. Grype/CVE-2018-20657 cross-references
// CVE-2018-12698 in its descriptions and code, and CVE-2018-12698 is not a
// requirement in this document at all — so `search` returns one false positive and
// zero true positives for it, and a gate written that way fires on an unrelated
// vulnerability. A glob on id reads only the id, so prose cannot reach it.
func TestFilterByID_SharedCases(t *testing.T) {
	table := loadIDCases(t)
	var results hdf.HDFResults
	require.NoError(t, json.Unmarshal(fixtures.Results.MergeGrype, &results))

	require.Len(t, ids(Filter(context.Background(), results, Options{StatusOf: testStatusOf})),
		table.UnfilteredCount, "the table describes a different fixture than the one loaded")

	for _, tc := range table.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := ids(Filter(context.Background(), results, Options{
				ID:       tc.ID,
				StatusOf: testStatusOf,
			}))
			if len(tc.Expect) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tc.Expect, got)
		})
	}
}

func TestValidTag(t *testing.T) {
	for _, tc := range loadTagCases(t).Validity {
		t.Run(tc.Value, func(t *testing.T) {
			assert.Equal(t, tc.Valid, ValidTag(tc.Value))
		})
	}
}

func TestValidBaselineLabel(t *testing.T) {
	for _, tc := range loadBaselineLabelCases(t).Validity {
		t.Run(tc.Value, func(t *testing.T) {
			assert.Equal(t, tc.Valid, ValidBaselineLabel(tc.Value))
		})
	}
}

// The second baseline carries NO labels, so it must never satisfy a label
// predicate — an absent label is not a wildcard. Asserted as an exclusion
// because an inclusion-only check passes against a filter that never ran.
func TestFilterByBaselineLabel_UnlabelledBaselineMatchesNothing(t *testing.T) {
	table := loadBaselineLabelCases(t)
	results := loadResultsFixture(t, table.FixtureFile)

	unfiltered := ids(Filter(context.Background(), results, Options{StatusOf: testStatusOf}))
	for _, id := range table.UnlabelledBaselineIDs {
		require.Contains(t, unfiltered, id,
			"precondition: the unlabelled baseline's requirements are reachable without the predicate")
	}

	got := ids(Filter(context.Background(), results, Options{
		BaselineLabel: In("environment:production"),
		StatusOf:      testStatusOf,
	}))
	for _, id := range table.UnlabelledBaselineIDs {
		assert.NotContains(t, got, id, "an unlabelled baseline must not match")
	}
	assert.NotEmpty(t, got, "and the labelled one must still match, or this proves nothing")
}

// A label value is exactly one string by schema, where a tag value may be a list.
// Reusing the tag matcher would have meant converting a map[string]string into
// map[string]any to ask a question the simpler shape answers directly.
func TestLabelMatchesGlob(t *testing.T) {
	labels := map[string]string{"environment": "production", "team": "platform-sre"}

	assert.True(t, labelMatchesGlob(labels, "environment", "production"))
	assert.True(t, labelMatchesGlob(labels, "environment", "prod*"))
	assert.True(t, labelMatchesGlob(labels, "team", "platform-*"))
	assert.False(t, labelMatchesGlob(labels, "environment", "staging"))
	assert.False(t, labelMatchesGlob(labels, "region", "*"), "an absent key matches nothing, not everything")
	assert.False(t, labelMatchesGlob(nil, "environment", "*"), "and neither does an absent map")
}
