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
	if nextCall != "status accepts only: passed, failed, notApplicable, notReviewed, error" {
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
	if nextCall != "severity accepts only: critical, high, medium, low, informational" {
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

// The two tools share one refusal, so the same typo cannot draw a refusal from
// one and a clean empty answer — or differently worded advice — from the other.
func TestQueryAndAggregateRefuseTheSameValueIdentically(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	aggRes, _ := callAggregate(t, aggregateInput{Sources: srcs, Status: []string{"faild"}})
	queryRes, _ := callQuery(t, queryInput{Source: handle.Source{Path: "query-results.json"}, Status: []string{"faild"}})
	if aggRes == nil || !aggRes.IsError || queryRes == nil || !queryRes.IsError {
		t.Fatal("both tools must refuse the same unknown status")
	}
	aggMessage, aggNext := argRefusal(t, aggRes)
	queryMessage, queryNext := argRefusal(t, queryRes)
	if aggMessage != queryMessage || aggNext != queryNext {
		t.Errorf("refusals differ:\n  hdf_aggregate: %q / %q\n  hdf_query:     %q / %q",
			aggMessage, aggNext, queryMessage, queryNext)
	}
	if aggMessage != `unknown status "faild"` {
		t.Errorf("message = %q, want `unknown status \"faild\"`", aggMessage)
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
