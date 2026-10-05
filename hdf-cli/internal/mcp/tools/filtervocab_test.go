package tools

import (
	"encoding/json"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// argRefusal decodes an argError payload so a test pins the message and the
// suggested next call exactly, not a substring of the JSON envelope.
func argRefusal(t *testing.T, res *sdkmcp.CallToolResult) (message, nextCall string) {
	t.Helper()
	var payload struct {
		Error    string `json:"error"`
		NextCall string `json:"nextCall"`
	}
	if err := json.Unmarshal([]byte(payloadText(t, res)), &payload); err != nil {
		t.Fatalf("refusal payload is not an argError envelope: %v", err)
	}
	return payload.Error, payload.NextCall
}

func TestOrList(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"empty", nil, ""},
		{"one", []string{"passed"}, "passed"},
		{"two", []string{"passed", "failed"}, "passed, or failed"},
		{"five", []string{"critical", "high", "medium", "low", "informational"}, "critical, high, medium, low, or informational"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orList(tt.in); got != tt.want {
				t.Errorf("orList(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// query-results.json holds exactly five requirements, one per bucket:
// V-PASS-01 (passed, high), V-FAIL-CRIT-02 (failed, critical),
// V-FAIL-MED-03 (failed, medium), V-NA-04 (notApplicable, informational) and
// V-ERR-LOW-05 (error, low). Nothing in it is notReviewed. Every assertion below
// names what each filter must exclude from that set.

func TestAggregate_UnknownStatusRefused(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	res, out := callAggregate(t, aggregateInput{Sources: srcs, Status: []string{"bogus_value"}})
	if res == nil || !res.IsError {
		t.Fatal("an unknown status must be refused with an isError result, not counted as an empty rollup")
	}
	message, nextCall := argRefusal(t, res)
	if message != `unknown status "bogus_value"` {
		t.Errorf("message = %q, want `unknown status \"bogus_value\"`", message)
	}
	if nextCall != "use status passed, failed, notApplicable, notReviewed, or error" {
		t.Errorf("nextCall = %q, want the legal status values", nextCall)
	}
	if out.Aggregate.Total != 0 || len(out.PerSource) != 0 {
		t.Errorf("a refused call must count nothing, got total %d over %d rollups", out.Aggregate.Total, len(out.PerSource))
	}
}

func TestAggregate_UnknownSeverityRefused(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	res, out := callAggregate(t, aggregateInput{Sources: srcs, Severity: []string{"catastrophic"}})
	if res == nil || !res.IsError {
		t.Fatal("an unknown severity must be refused with an isError result")
	}
	message, nextCall := argRefusal(t, res)
	if message != `unknown severity "catastrophic"` {
		t.Errorf("message = %q, want `unknown severity \"catastrophic\"`", message)
	}
	if nextCall != "use severity critical, high, medium, low, or informational" {
		t.Errorf("nextCall = %q, want the legal severity values", nextCall)
	}
	if out.Aggregate.Total != 0 {
		t.Errorf("a refused call must count nothing, got total %d", out.Aggregate.Total)
	}
}

// A bad value among good ones is still refused — the first unknown value is
// named, so a caller fixing a list is told which entry is wrong.
func TestAggregate_UnknownStatusAmongValidOnesRefused(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	res, _ := callAggregate(t, aggregateInput{Sources: srcs, Status: []string{"failed", "fail"}})
	if res == nil || !res.IsError {
		t.Fatal("one unknown status among valid ones must still refuse the call")
	}
	if message, _ := argRefusal(t, res); message != `unknown status "fail"` {
		t.Errorf("message = %q, want the unknown entry named", message)
	}
}

// The CLI's snake_case spellings are accepted and select the same requirement
// the schema spelling does. notApplicable matches V-NA-04 only, excluding
// V-PASS-01, V-FAIL-CRIT-02, V-FAIL-MED-03 and V-ERR-LOW-05.
func TestAggregate_StatusAliasAccepted(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	res, out := callAggregate(t, aggregateInput{Sources: srcs, Status: []string{"not_applicable"}})
	if res != nil && res.IsError {
		t.Fatalf("not_applicable is an accepted spelling: %s", payloadText(t, res))
	}
	if out.Aggregate.Total != 1 {
		t.Errorf("not_applicable total = %d, want 1 (V-NA-04 only)", out.Aggregate.Total)
	}
	if got := out.Aggregate.Counts["no_impact"]["total"]; got != 1 {
		t.Errorf("no_impact bucket = %d, want 1 (V-NA-04)", got)
	}
	for _, excluded := range []string{"passed", "failed", "error", "skipped"} {
		if got := out.Aggregate.Counts[excluded]["total"]; got != 0 {
			t.Errorf("%s bucket = %d, want 0 (V-PASS-01/V-FAIL-*/V-ERR-LOW-05 are excluded)", excluded, got)
		}
	}
}

// not_reviewed is accepted and legitimately matches nothing in this fixture —
// an empty rollup here must look nothing like the refusal path above.
func TestAggregate_ValidFilterMatchingNothingIsNotARefusal(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	res, out := callAggregate(t, aggregateInput{Sources: srcs, Status: []string{"not_reviewed"}})
	if res != nil && res.IsError {
		t.Fatalf("not_reviewed is a legal status; an empty match set is a result, not an error: %s", payloadText(t, res))
	}
	if out.Aggregate.Total != 0 {
		t.Errorf("not_reviewed total = %d, want 0 (no requirement in the fixture is notReviewed)", out.Aggregate.Total)
	}
	if out.SourceCount != 1 {
		t.Errorf("sourceCount = %d, want 1 (the source loaded fine)", out.SourceCount)
	}
}

// The pre-3.7 "none" severity spelling still selects informational — V-NA-04 at
// impact 0.0 — and excludes the critical/high/medium/low requirements.
func TestAggregate_SeverityNoneAliasAccepted(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	res, out := callAggregate(t, aggregateInput{Sources: srcs, Severity: []string{"none"}})
	if res != nil && res.IsError {
		t.Fatalf("none is the accepted pre-3.7 spelling of informational: %s", payloadText(t, res))
	}
	if out.Aggregate.Total != 1 {
		t.Errorf("severity none total = %d, want 1 (V-NA-04 only; V-PASS-01 high, V-FAIL-CRIT-02 critical, V-FAIL-MED-03 medium and V-ERR-LOW-05 low are excluded)", out.Aggregate.Total)
	}
	if got := out.Aggregate.Counts["no_impact"]["informational"]; got != 1 {
		t.Errorf("no_impact/informational = %d, want 1 (V-NA-04)", got)
	}
}

// hdf_query shares the refusal with hdf_aggregate, so the two sibling tools give
// an agent the same answer for the same bad filter.
func TestQuery_UnknownStatusRefused(t *testing.T) {
	path := writeRoot(t, "query-results.json", readToolsFixture(t, "query-results.json"))
	res, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Status: []string{"bogus_value"}})
	if res == nil || !res.IsError {
		t.Fatal("an unknown status must be refused with an isError result")
	}
	message, nextCall := argRefusal(t, res)
	if message != `unknown status "bogus_value"` {
		t.Errorf("message = %q, want the same wording hdf_aggregate uses", message)
	}
	if nextCall != "use status passed, failed, notApplicable, notReviewed, or error" {
		t.Errorf("nextCall = %q, want the legal status values", nextCall)
	}
	if len(out.Requirements) != 0 {
		t.Errorf("a refused query must return no rows, got %d", len(out.Requirements))
	}
}

func TestQuery_UnknownSeverityRefused(t *testing.T) {
	path := writeRoot(t, "query-results.json", readToolsFixture(t, "query-results.json"))
	res, _ := callQuery(t, queryInput{Source: handle.Source{Path: path}, Severity: []string{"catastrophic"}})
	if res == nil || !res.IsError {
		t.Fatal("an unknown severity must be refused with an isError result")
	}
	if message, _ := argRefusal(t, res); message != `unknown severity "catastrophic"` {
		t.Errorf("message = %q, want the same wording hdf_aggregate uses", message)
	}
}

// The accepted spellings reach the engine canonicalized, so a snake_case filter
// returns the row the schema spelling returns rather than nothing.
func TestQuery_StatusAliasSelectsTheSameRow(t *testing.T) {
	path := writeRoot(t, "query-results.json", readToolsFixture(t, "query-results.json"))
	res, out := callQuery(t, queryInput{Source: handle.Source{Path: path}, Status: []string{"not_applicable"}})
	if res != nil && res.IsError {
		t.Fatalf("not_applicable is an accepted spelling: %s", payloadText(t, res))
	}
	if out.Total != 1 {
		t.Fatalf("not_applicable total = %d, want 1 (V-NA-04 only)", out.Total)
	}
	if got := out.Requirements[0]["id"]; got != "V-NA-04" {
		t.Errorf("matched id = %v, want V-NA-04 (V-PASS-01, V-FAIL-CRIT-02, V-FAIL-MED-03 and V-ERR-LOW-05 are excluded)", got)
	}
}
