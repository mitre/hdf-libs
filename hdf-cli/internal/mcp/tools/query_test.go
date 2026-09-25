package tools

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
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
	if res != nil && res.IsError {
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
	if res != nil && res.IsError {
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

// queryInput was written against the filter surface as it stood and did not
// track it: disposition and poams were added to the engine and the CLI by one
// card, rawImpact by another, and none reached the MCP. Nothing failed when the
// surfaces diverged, which is why the gap widened to three keys unnoticed.
//
// This is the guard, not the sweep. Every user-facing field on the engine's
// Options must be reachable through the tool or listed below with a reason, so a
// future filter key cannot be added to the engine and silently skip the MCP.
//
// What it does NOT catch: a field present on queryInput but never passed to the
// engine, or passed without a vocabulary check. Those are covered for the
// current keys by the behavioural tests below, which assert what each filter
// EXCLUDES — an inclusion-only assertion passes against a filter that never ran,
// since an absent filter returns everything.
func TestQueryInputCoversEveryEngineFilter(t *testing.T) {
	// Not filters: these are how the CALLER drives the engine, not what a user
	// selects by. Each is either supplied by the tool itself or exposed under a
	// different name that the tool owns.
	notAFilter := map[string]string{
		"Now":      "reference clock, supplied by the tool rather than the caller",
		"Count":    "the tool always requests every match and pages the result itself",
		"StatusOf": "the status resolver the tool injects; not a value a caller picks",
		"Limit":    "exposed as the tool's own Limit/Page pair, which paginate the response",
	}

	options := reflect.TypeOf(hdfengine.Options{})
	input := reflect.TypeOf(queryInput{})
	for i := 0; i < options.NumField(); i++ {
		name := options.Field(i).Name
		if reason, ok := notAFilter[name]; ok {
			if reason == "" {
				t.Errorf("%s is excluded without a reason", name)
			}
			continue
		}
		if _, found := input.FieldByName(name); !found {
			t.Errorf("engine filter %q is not reachable through hdf_query and is not listed as a non-filter — "+
				"an agent cannot ask what a CLI user can", name)
		}
	}
}

// amendedResults is the minimum document that can tell the three amendments
// filters apart: one requirement waived, one risk-adjusted from 0.9 to 0.3, one
// carrying a live POA&M, one plain. A fixture without them would let every
// assertion below pass against a filter that never reached the engine.
func amendedResults(t *testing.T) string {
	t.Helper()
	const doc = `{
  "generator": {"name": "test", "version": "1"},
  "timestamp": "2026-01-01T00:00:00Z",
  "statistics": {"duration": 1.0},
  "baselines": [{"name": "b", "requirements": [
    {"id": "PLAIN", "title": "no amendment", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}]},
    {"id": "WAIVED", "title": "waived", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}],
     "statusOverrides": [{"type": "waiver", "status": "passed", "reason": "compensating control",
       "appliedBy": {"type": "simple", "identifier": "t"},
       "appliedAt": "2024-06-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z"}]},
    {"id": "ADJUSTED", "title": "risk-adjusted", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}],
     "statusOverrides": [{"type": "riskAdjustment", "reason": "environmental context",
       "appliedBy": {"type": "simple", "identifier": "t"},
       "appliedAt": "2024-06-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z",
       "impact": {"value": 0.3}}]},
    {"id": "LOW", "title": "below every bound the tests use", "impact": 0.1, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}]},
    {"id": "PLANNED", "title": "has a live plan", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}],
     "poams": [{"type": "remediation", "explanation": "remediation scheduled",
       "appliedBy": {"type": "simple", "identifier": "t"},
       "appliedAt": "2024-06-01T00:00:00Z", "expiresAt": "2099-12-31T00:00:00Z"}]}
  ]}]
}`
	return writeRoot(t, "amended.json", []byte(doc))
}

func queryIDs(t *testing.T, in queryInput) []string {
	t.Helper()
	_, out := callQuery(t, in)
	ids := make([]string, 0, len(out.Requirements))
	for _, r := range out.Requirements {
		if id, ok := r["id"].(string); ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// The three keys must SELECT, not merely be accepted. Each assertion names what
// the filter excludes as well as what it includes, so a filter that never
// reached the engine — and therefore returned everything — fails here.
func TestQuery_AmendmentFiltersReachTheEngine(t *testing.T) {
	path := amendedResults(t)
	src := handle.Source{Path: path}

	for _, tc := range []struct {
		name string
		in   queryInput
		want []string
	}{
		{"disposition selects the governing override's type",
			queryInput{Source: src, Disposition: []string{"riskAdjustment"}}, []string{"ADJUSTED"}},
		{"disposition ORs across values",
			queryInput{Source: src, Disposition: []string{"waiver", "riskAdjustment"}}, []string{"ADJUSTED", "WAIVED"}},
		{"poams valid finds the requirement carrying a live plan",
			queryInput{Source: src, Poams: "valid"}, []string{"PLANNED"}},
		{"poams none-valid collapses absent and empty",
			queryInput{Source: src, Poams: "none-valid"}, []string{"ADJUSTED", "LOW", "PLAIN", "WAIVED"}},
		{"impact is the EFFECTIVE score, so the adjusted requirement leaves the band it was re-scored from",
			queryInput{Source: src, Impact: ">=0.9"}, []string{"PLAIN", "PLANNED", "WAIVED"}},
		{"rawImpact reaches the score the adjustment moved it from",
			queryInput{Source: src, RawImpact: ">=0.9"}, []string{"ADJUSTED", "PLAIN", "PLANNED", "WAIVED"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := queryIDs(t, tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// vulnResults is the minimum document that can tell the four vulnerability
// filters apart, including one requirement each bound below must EXCLUDE: the
// guard test proves the FIELD exists on queryInput, not that it reaches the
// engine, and an absent filter returns everything.
func vulnResults(t *testing.T) string {
	t.Helper()
	const doc = `{
  "generator": {"name": "test", "version": "1"},
  "timestamp": "2026-01-01T00:00:00Z",
  "statistics": {"duration": 1.0},
  "baselines": [{"name": "b", "requirements": [
    {"id": "KEV", "title": "critical, known exploited", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}],
     "cvss": [{"version": "3.1", "baseScore": 9.8}],
     "epss": {"score": 0.944, "percentile": 0.999, "date": "2026-01-01"},
     "kev": {"inKev": true, "dateAdded": "2021-12-10", "dueDate": "2021-12-24"},
     "cwe": ["CWE-502"]},
    {"id": "ENRICHED", "title": "vendor 9.8, recomputed to 5.2", "impact": 0.9, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}],
     "cvss": [{"version": "3.1", "baseScore": 9.8, "threatVector": "E:U", "threatScore": 5.2, "computedScore": 5.2}],
     "epss": {"score": 0.02, "percentile": 0.41, "date": "2026-01-01"},
     "kev": {"inKev": false},
     "cwe": ["CWE-79"]},
    {"id": "LOW", "title": "below every bound here", "impact": 0.3, "tags": {},
     "descriptions": [{"label": "default", "data": "d"}],
     "results": [{"status": "failed", "codeDesc": "c", "startTime": "2024-01-01T00:00:00Z"}],
     "cvss": [{"version": "3.1", "baseScore": 2.1}],
     "epss": {"score": 0.001, "percentile": 0.05, "date": "2026-01-01"}}
  ]}]
}`
	return writeRoot(t, "vulns.json", []byte(doc))
}

// The four keys must SELECT, not merely be accepted. Each case names what the
// filter excludes as well as what it includes — removing the wiring from the
// Options literal previously left the whole MCP suite green.
func TestQuery_VulnerabilityFiltersReachTheEngine(t *testing.T) {
	src := handle.Source{Path: vulnResults(t)}
	for _, tc := range []struct {
		name string
		in   queryInput
		want []string
	}{
		{"cvss compares the recomputed score, not the vendor base score",
			queryInput{Source: src, Cvss: ">=7"}, []string{"KEV"}},
		{"and finds the enriched one in the band it was recomputed into",
			queryInput{Source: src, Cvss: ">=5"}, []string{"ENRICHED", "KEV"}},
		{"epss is the probability, so the 0.999 percentile row is not what matches",
			queryInput{Source: src, Epss: ">=0.5"}, []string{"KEV"}},
		{"kev true selects only the catalogued finding",
			queryInput{Source: src, Kev: "true"}, []string{"KEV"}},
		{"kev false covers inKev:false and an absent block alike",
			queryInput{Source: src, Kev: "false"}, []string{"ENRICHED", "LOW"}},
		{"cwe matches numerically, whatever the spelling",
			queryInput{Source: src, Cwe: []string{"cwe502"}}, []string{"KEV"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := queryIDs(t, tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// The vulnerability half of the refusal contract below.
func TestQuery_VulnerabilityFiltersRefuseBadValues(t *testing.T) {
	src := handle.Source{Path: vulnResults(t)}
	for _, tc := range []struct {
		name string
		in   queryInput
		want string
	}{
		{"cvss", queryInput{Source: src, Cvss: ">>7"}, "invalid cvss filter"},
		{"epss", queryInput{Source: src, Epss: "~0.5"}, "invalid epss filter"},
		{"kev", queryInput{Source: src, Kev: "yes"}, "unknown kev filter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := callQuery(t, tc.in)
			if txt := payloadText(t, res); !strings.Contains(txt, tc.want) {
				t.Errorf("want refusal containing %q, got %s", tc.want, txt)
			}
		})
	}
}

// An unrecognized value must be REFUSED, not matched against nothing. To an
// agent a clean empty result reads as "asked and found none", which is the false
// green this vocabulary exists to prevent — and it has no way to tell the two
// apart without the refusal.
func TestQuery_AmendmentFiltersRefuseUnknownValues(t *testing.T) {
	path := amendedResults(t)
	src := handle.Source{Path: path}

	for _, tc := range []struct {
		name string
		in   queryInput
		want string
	}{
		{"disposition", queryInput{Source: src, Disposition: []string{"waver"}}, "unknown disposition"},
		{"poams", queryInput{Source: src, Poams: "absent"}, "unknown poams filter"},
		{"rawImpact", queryInput{Source: src, RawImpact: ">>7"}, "invalid rawImpact filter"},
		{"impact", queryInput{Source: src, Impact: ">>7"}, "invalid impact filter"},
		// The CLI has refused these two since the vocabulary landed; the MCP
		// never did, so an agent's typo read as a clean empty result.
		{"status", queryInput{Source: src, Status: []string{"faild"}}, "unknown status"},
		{"severity", queryInput{Source: src, Severity: []string{"crit"}}, "unknown severity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := callQuery(t, tc.in)
			txt := payloadText(t, res)
			if !strings.Contains(txt, tc.want) {
				t.Errorf("want refusal containing %q, got %s", tc.want, txt)
			}
		})
	}
}
