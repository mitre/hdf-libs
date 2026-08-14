package tools

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callQuery(t *testing.T, in queryInput) (*sdkmcp.CallToolResult, queryOutput) {
	t.Helper()
	res, out, err := hdfQuery(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfQuery Go error (should be taxonomy tool result): %v", err)
	}
	return res, out
}

// toolResultPayload decodes the structured taxonomy payload from an isError
// tool result so tests can assert the code + next call.
func toolResultPayload(t *testing.T, res *sdkmcp.CallToolResult) mcperr.ToolResult {
	t.Helper()
	var tr mcperr.ToolResult
	if err := json.Unmarshal([]byte(payloadText(t, res)), &tr); err != nil {
		t.Fatalf("decode tool-result payload: %v (raw %q)", err, payloadText(t, res))
	}
	return tr
}

func ids(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, m := range rows {
		if id, ok := m["id"].(string); ok {
			out = append(out, id)
		}
	}
	return out
}

// The card's designated first-failing test: a non-results/baseline document
// (here a system document) returns WRONG_DOC_TYPE whose remedy names hdf_inspect.
func TestHdfQuery_SystemDoc_ReturnsWrongDocType(t *testing.T) {
	path := writeRoot(t, "system.json", readCLIFixture(t, "system.json"))
	res, _ := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	if res == nil || !res.IsError {
		t.Fatal("a system document must return an isError result, not a query answer")
	}
	tr := toolResultPayload(t, res)
	if tr.Code != mcperr.WrongDocType {
		t.Errorf("code = %q, want WRONG_DOC_TYPE", tr.Code)
	}
	if !strings.Contains(tr.NextCall, "hdf_inspect") {
		t.Errorf("WRONG_DOC_TYPE remedy must name hdf_inspect, got %q", tr.NextCall)
	}
}

// Every non-requirement document type is rejected the same way — the enforced
// other half of the hdf_inspect/hdf_query bright line.
func TestHdfQuery_RejectsAllNonRequirementTypes(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
	}{
		{"system.json", readCLIFixture(t, "system.json")},
		{"plan.json", readCLIFixture(t, "plan.json")},
		{"evidence.json", readCLIFixture(t, "evidence.json")},
		{"amendments.json", fixtures.Amendments.UC01Fixed},
		{"comparison.json", readToolsFixture(t, "comparison.json")},
		{"change-event.json", readToolsFixture(t, "change-event.json")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeRoot(t, c.name, c.content)
			res, _ := callQuery(t, queryInput{Source: handle.Source{Path: path}})
			if res == nil || !res.IsError {
				t.Fatalf("%s must be rejected with an isError result", c.name)
			}
			tr := toolResultPayload(t, res)
			if tr.Code != mcperr.WrongDocType {
				t.Errorf("%s: code = %q, want WRONG_DOC_TYPE", c.name, tr.Code)
			}
			if !strings.Contains(tr.NextCall, "hdf_inspect") {
				t.Errorf("%s: remedy must name hdf_inspect, got %q", c.name, tr.NextCall)
			}
		})
	}
}

func TestHdfQuery_ResultsDelegatesFilters(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))

	// status=failed → exactly the two failed requirements (engine-delegated).
	res, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Status: []string{"failed"}})
	if res != nil {
		t.Fatalf("valid results query must not error: %s", payloadText(t, res))
	}
	got := ids(out.Requirements)
	sort.Strings(got)
	want := []string{"V-FAIL-CRIT-02", "V-FAIL-MED-03"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("status=failed ids = %v, want %v", got, want)
	}
	if out.Total != 2 || out.Returned != 2 {
		t.Errorf("total/returned = %d/%d, want 2/2", out.Total, out.Returned)
	}

	// nist=CM-6 → exactly the one medium-severity failure.
	_, nistOut := callQuery(t, queryInput{Source: handle.Source{Path: path}, NIST: []string{"CM-6"}})
	if g := ids(nistOut.Requirements); len(g) != 1 || g[0] != "V-FAIL-MED-03" {
		t.Errorf("nist=CM-6 ids = %v, want [V-FAIL-MED-03]", g)
	}

	// impact >0.8 → only the critical failure.
	_, impOut := callQuery(t, queryInput{Source: handle.Source{Path: path}, Impact: ">0.8"})
	if g := ids(impOut.Requirements); len(g) != 1 || g[0] != "V-FAIL-CRIT-02" {
		t.Errorf("impact>0.8 ids = %v, want [V-FAIL-CRIT-02]", g)
	}

	// cci filter delegates too.
	_, cciOut := callQuery(t, queryInput{Source: handle.Source{Path: path}, CCI: []string{"CCI-000172"}})
	if g := ids(cciOut.Requirements); len(g) != 1 || g[0] != "V-FAIL-MED-03" {
		t.Errorf("cci=CCI-000172 ids = %v, want [V-FAIL-MED-03]", g)
	}
}

// Status is reported in the schema (effectiveStatus) vocabulary — the same
// vocabulary hdf_open's summary uses — not the CLI underscore display form.
func TestHdfQuery_StatusVocabulary(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	_, out := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	byID := map[string]string{}
	for _, r := range out.Requirements {
		b, _ := json.Marshal(r)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		byID[m["id"].(string)] = m["status"].(string)
	}
	want := map[string]string{
		"V-PASS-01":      "passed",
		"V-FAIL-CRIT-02": "failed",
		"V-NA-04":        "notApplicable",
		"V-ERR-LOW-05":   "error",
	}
	for id, st := range want {
		if byID[id] != st {
			t.Errorf("status[%s] = %q, want %q", id, byID[id], st)
		}
	}
	// A status[] filter uses that same vocabulary.
	_, naOut := callQuery(t, queryInput{Source: handle.Source{Path: path}, Status: []string{"notApplicable"}})
	if g := ids(naOut.Requirements); len(g) != 1 || g[0] != "V-NA-04" {
		t.Errorf("status=notApplicable ids = %v, want [V-NA-04]", g)
	}
}

// Concise rows carry EXACTLY id, title, status, severity, impact — no more, no fewer.
func TestHdfQuery_ConciseShape_ExactFields(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	_, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Verbosity: "concise"})
	if len(out.Requirements) == 0 {
		t.Fatal("expected requirement rows")
	}
	want := []string{"id", "impact", "severity", "status", "title"}
	for _, r := range out.Requirements {
		b, _ := json.Marshal(r)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		got := make([]string, 0, len(m))
		for k := range m {
			got = append(got, k)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("concise row keys = %v, want exactly %v", got, want)
		}
	}
}

// Full rows are richer than concise — they add at least the baseline plus the
// requirement's tags (NIST/CCI) — still within the full-tier token cap.
func TestHdfQuery_FullShape_Richer(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	_, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Verbosity: "full", Status: []string{"failed"}})
	if len(out.Requirements) == 0 {
		t.Fatal("expected requirement rows")
	}
	for _, r := range out.Requirements {
		b, _ := json.Marshal(r)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		for _, k := range []string{"id", "title", "status", "severity", "impact", "baseline", "tags"} {
			if _, ok := m[k]; !ok {
				t.Errorf("full row missing %q; keys %v", k, keysOf(m))
			}
		}
	}
}

// Baseline documents are the second requirement-bearing type: their requirements
// filter through the same engine (an un-run baseline requirement is notReviewed,
// or notApplicable at impact 0).
func TestHdfQuery_BaselineDocument(t *testing.T) {
	path := writeRoot(t, "baseline.json", fixtures.Baseline.Win2022Stig)
	res, out := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	if res != nil {
		t.Fatalf("a baseline document must be queryable, got error: %s", payloadText(t, res))
	}
	if out.DocType != "baseline" {
		t.Errorf("docType = %q, want baseline", out.DocType)
	}
	if out.Total == 0 || len(out.Requirements) == 0 {
		t.Fatal("baseline query should return its requirements")
	}
	for _, r := range out.Requirements {
		b, _ := json.Marshal(r)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		st := m["status"].(string)
		if st != "notReviewed" && st != "notApplicable" {
			t.Errorf("un-run baseline requirement status = %q, want notReviewed/notApplicable", st)
		}
	}
}

func TestHdfQuery_Envelope(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	_, out := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	if out.Total != 5 {
		t.Errorf("total = %d, want 5 (all requirements)", out.Total)
	}
	if out.Returned != len(out.Requirements) {
		t.Errorf("returned (%d) must equal len(requirements) (%d)", out.Returned, len(out.Requirements))
	}
	if out.Handle == "" || out.DocType != "results" {
		t.Errorf("envelope must carry a handle + docType, got handle=%q docType=%q", out.Handle, out.DocType)
	}
}

// limit caps the candidate window while total still reports the true universe,
// and a hidden remainder is flagged truncated with a narrowing notice.
func TestHdfQuery_LimitCapsWithNotice(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	_, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Limit: 2})
	if out.Returned != 2 {
		t.Errorf("returned = %d, want 2 (limit)", out.Returned)
	}
	if out.Total != 5 {
		t.Errorf("total = %d, want 5 (true universe, not the limit)", out.Total)
	}
	if !out.Truncated || out.Notice == "" {
		t.Error("a limit that hides matches must set truncated + a notice")
	}
}

// Functional pagination over a large result set: page 1 returns different rows
// than page 0, and the truncation notice names a narrowing parameter.
func TestHdfQuery_PaginationFunctional(t *testing.T) {
	path := writeRoot(t, "big.json", fixtures.Results.InspecMultilayered)
	_, p0 := callQuery(t, queryInput{Source: handle.Source{Path: path}, Verbosity: "concise"})
	if !p0.Truncated || p0.NextPage != 1 {
		t.Fatalf("a large result set must truncate with nextPage=1, got truncated=%v next=%d total=%d returned=%d",
			p0.Truncated, p0.NextPage, p0.Total, p0.Returned)
	}
	if p0.Notice == "" || !strings.Contains(p0.Notice, "page=1") {
		t.Errorf("truncation notice must name the next page, got %q", p0.Notice)
	}
	_, p1 := callQuery(t, queryInput{Source: handle.Source{Path: path}, Verbosity: "concise", Page: 1})
	j0, _ := json.Marshal(p0.Requirements)
	j1, _ := json.Marshal(p1.Requirements)
	if string(j0) == string(j1) {
		t.Error("page 1 returned the same rows as page 0 — paging is not advancing")
	}
	if len(p1.Requirements) == 0 {
		t.Error("page 1 should return the next window of rows")
	}
}

// The limit-capped truncation notice must advise raising/removing limit (not a
// smaller limit), and must not read as self-contradictory. Regression for lj0g.6.
func TestHdfQuery_LimitNoticeAdvisesRaiseNotShrink(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	_, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Limit: 2})
	if !out.Truncated || out.Notice == "" {
		t.Fatal("a limit that hides matches must truncate with a notice")
	}
	n := out.Notice
	if strings.Contains(n, "smaller limit to see") || strings.Contains(n, "a smaller limit or") {
		t.Errorf("notice must not advise a smaller limit to see more rows: %q", n)
	}
	if !strings.Contains(n, "Raise or remove limit") {
		t.Errorf("notice should advise raising/removing limit, got %q", n)
	}
	if !strings.Contains(n, "page=N") {
		t.Errorf("notice should point at paging for the unlimited result, got %q", n)
	}
}

func TestHdfQuery_PageOutOfRange(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	_, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Page: 99})
	if len(out.Requirements) != 0 || !out.Truncated || out.Notice == "" {
		t.Errorf("an out-of-range page must return no rows + a notice, got %+v", out)
	}
}

func TestHdfQuery_SchemaInvalidResults(t *testing.T) {
	// Detected results but schema-invalid (impact out of range) → SCHEMA_INVALID,
	// not a partial answer.
	bad := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"x","descriptions":[],"impact":5,"tags":{},"results":[]}]}],"statistics":{"duration":1}}`)
	path := writeRoot(t, "bad.json", bad)
	res, _ := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	if res == nil || !res.IsError {
		t.Fatal("a schema-invalid results doc must error, not answer")
	}
	if tr := toolResultPayload(t, res); tr.Code != mcperr.SchemaInvalid {
		t.Errorf("code = %q, want SCHEMA_INVALID", tr.Code)
	}
}

func TestHdfQuery_Annotations(t *testing.T) {
	s := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "t", Version: "v"}, nil)
	RegisterQuery(s, loader.New(0, 0, 0))
	raw := driveToolsListJSON(t, s)
	if !strings.Contains(raw, `"name":"hdf_query"`) {
		t.Fatalf("hdf_query not listed: %s", raw)
	}
	if !strings.Contains(raw, `"readOnlyHint":true`) || !strings.Contains(raw, `"openWorldHint":false`) {
		t.Errorf("hdf_query must be read-only + closed-world: %s", raw)
	}
}

// The dispatch hook is additive: results/baseline are registered, and a type
// added to the registry becomes queryable WITHOUT touching hdfQuery's body.
func TestHdfQuery_DispatchHookIsAdditive(t *testing.T) {
	for _, dt := range []string{"results", "baseline"} {
		if _, ok := queryDispatch[dt]; !ok {
			t.Errorf("queryDispatch must handle %q", dt)
		}
	}
	if _, ok := queryDispatch["system"]; ok {
		t.Error("cross-document filtering must NOT be implemented here — system must be absent")
	}

	// Registering a new type is purely additive: hdfQuery resolves it via the map,
	// so a temporary registration makes that type queryable with no body change.
	defer func() { delete(queryDispatch, "system") }()
	queryDispatch["system"] = queryDispatch["results"]
	path := writeRoot(t, "system.json", readCLIFixture(t, "system.json"))
	res, _ := callQuery(t, queryInput{Source: handle.Source{Path: path}})
	if res != nil && res.IsError {
		if tr := toolResultPayload(t, res); tr.Code == mcperr.WrongDocType {
			t.Error("with system registered, hdfQuery must dispatch it rather than returning WRONG_DOC_TYPE")
		}
	}
}

func TestPaginateRows_DisjointWindows(t *testing.T) {
	rows := make([]map[string]any, 0, 200)
	for i := 0; i < 200; i++ {
		rows = append(rows, structToMap(conciseRow{
			ID:    "REQ-" + string(rune('A'+i%26)) + strings.Repeat("x", 3) + itoa(i),
			Title: strings.Repeat("requirement title padding ", 4), Status: "failed",
			Severity: "high", Impact: 0.7,
		}))
	}
	base := queryOutput{Handle: "h", DocType: "results"}
	sizeOf := func(page []map[string]any) int {
		trial := base
		trial.Requirements = page
		trial.Truncated = true
		trial.NextPage = 1
		return respond.EstimateTokens(mustJSON(&trial))
	}
	pages := respond.Paginate(rows, 800, sizeOf)
	if len(pages) < 2 {
		t.Fatalf("expected multiple pages, got %d", len(pages))
	}
	seen := map[string]bool{}
	for _, pg := range pages {
		for _, id := range ids(pg) {
			if seen[id] {
				t.Errorf("id %q appeared on more than one page — pages must be disjoint", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 200 {
		t.Errorf("pages must cover every row exactly once, covered %d of 200", len(seen))
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestHdfQuery_RejectsMalformedImpact(t *testing.T) {
	path := writeRoot(t, "q.json", readToolsFixture(t, "query-results.json"))
	res, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Impact: ">x"})
	if res == nil {
		t.Fatal("a malformed impact filter must be refused (argError), not silently return impact==0 rows")
	}
	if len(out.Requirements) != 0 {
		t.Fatalf("refused query must return no rows, got %d", len(out.Requirements))
	}
}
