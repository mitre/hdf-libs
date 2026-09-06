package tools

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func callAggregate(t *testing.T, in aggregateInput) (*sdkmcp.CallToolResult, aggregateOutput) {
	t.Helper()
	res, out, err := hdfAggregate(loader.New(0, 0, 0))(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("hdfAggregate Go error (should be a taxonomy tool result): %v", err)
	}
	return res, out
}

// sources writes each named fixture under one HDF_MCP_ROOT and returns Source
// values addressing them by relative path.
func sourcesUnderRoot(t *testing.T, names ...string) []handle.Source {
	t.Helper()
	files := map[string][]byte{}
	for _, n := range names {
		files[n] = readToolsFixture(t, filepath.Base(n))
	}
	writeRootFiles(t, files)
	out := make([]handle.Source, 0, len(names))
	for _, n := range names {
		out = append(out, handle.Source{Path: n})
	}
	return out
}

// TestAggregate_MultipleSources is y6t5's designated first-failing test: one call
// over several documents returns a per-source breakdown AND a server-side total,
// so the model never sums across turns.
func TestAggregate_MultipleSources(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json", "correlation-results.json")
	res, out := callAggregate(t, aggregateInput{Sources: srcs})
	if res != nil && res.IsError {
		t.Fatalf("multi-source aggregate must not error: %s", payloadText(t, res))
	}
	if len(out.PerSource) != 2 {
		t.Fatalf("expected 2 per-source rollups, got %d", len(out.PerSource))
	}
	// query-results has 5 requirements, correlation-results has 2 → aggregate 7.
	if out.Aggregate.Total != 7 {
		t.Errorf("aggregate total = %d, want 7 (5 + 2)", out.Aggregate.Total)
	}
	// Across both docs: 2 failed (query) + 2 failed (correlation) = 4 failed.
	if got := out.Aggregate.Counts["failed"]["total"]; got != 4 {
		t.Errorf("aggregate failed total = %d, want 4", got)
	}
	// Per-source totals are present and correct.
	bySource := map[string]int{}
	for _, ps := range out.PerSource {
		bySource[ps.Source] = ps.Total
	}
	if bySource["query-results.json"] != 5 {
		t.Errorf("query-results per-source total = %d, want 5", bySource["query-results.json"])
	}
	if bySource["correlation-results.json"] != 2 {
		t.Errorf("correlation-results per-source total = %d, want 2", bySource["correlation-results.json"])
	}
}

// TestAggregate_SeverityFilter narrows the counted set: only critical-severity
// requirements are counted, server-side, across all sources.
func TestAggregate_SeverityFilter(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json", "correlation-results.json")
	_, out := callAggregate(t, aggregateInput{Sources: srcs, Severity: []string{"critical"}})
	// Only V-FAIL-CRIT-02 (impact 0.95) is critical across both docs.
	if out.Aggregate.Total != 1 {
		t.Errorf("critical-only aggregate total = %d, want 1", out.Aggregate.Total)
	}
}

// TestAggregate_PartialFailure: a source that fails to load is reported in
// failures[] and the call still answers for the rest (AC4).
func TestAggregate_PartialFailure(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json")
	srcs = append(srcs, handle.Source{Path: "does-not-exist.json"})
	res, out := callAggregate(t, aggregateInput{Sources: srcs})
	if res != nil && res.IsError {
		t.Fatalf("partial failure must not fail the whole call: %s", payloadText(t, res))
	}
	if len(out.PerSource) != 1 || out.PerSource[0].Total != 5 {
		t.Fatalf("the loadable source must still be aggregated (5 reqs); got %+v", out.PerSource)
	}
	if len(out.Failures) != 1 {
		t.Fatalf("expected 1 failure entry, got %d", len(out.Failures))
	}
	if out.Failures[0].Index != 1 {
		t.Errorf("failure index = %d, want 1 (second source)", out.Failures[0].Index)
	}
	if out.Aggregate.Total != 5 {
		t.Errorf("aggregate total = %d, want 5 (failed source excluded)", out.Aggregate.Total)
	}
}

// TestAggregate_EmptySourcesErrors: an empty sources list is a caller mistake.
func TestAggregate_EmptySourcesErrors(t *testing.T) {
	res, out := callAggregate(t, aggregateInput{Sources: nil})
	if res == nil || !res.IsError {
		t.Fatal("empty sources must be refused with an isError result")
	}
	if len(out.PerSource) != 0 {
		t.Errorf("a refused call must return no rollups, got %d", len(out.PerSource))
	}
}

// TestAggregate_WrongDocTypeIsFailure: a non-requirement document (a system doc)
// among the sources is reported as a failure, not silently counted, and the rest
// still aggregate.
func TestAggregate_WrongDocTypeIsFailure(t *testing.T) {
	writeRootFiles(t, map[string][]byte{
		"results.json": readToolsFixture(t, "query-results.json"),
		"system.json":  readCLIFixture(t, "system.json"),
	})
	_, out := callAggregate(t, aggregateInput{Sources: []handle.Source{
		{Path: "results.json"}, {Path: "system.json"},
	}})
	if len(out.PerSource) != 1 || out.PerSource[0].Total != 5 {
		t.Fatalf("only the results doc should aggregate; got %+v", out.PerSource)
	}
	if len(out.Failures) != 1 || out.Failures[0].Index != 1 {
		t.Fatalf("the system doc must be a failure at index 1; got %+v", out.Failures)
	}
	if out.Aggregate.Total != 5 {
		t.Errorf("aggregate total = %d, want 5", out.Aggregate.Total)
	}
}

// TestAggregate_PageOutOfRange: a page past the end returns no rollups with an
// explicit notice, while the aggregate totals remain complete.
func TestAggregate_PageOutOfRange(t *testing.T) {
	srcs := sourcesUnderRoot(t, "query-results.json", "correlation-results.json")
	_, out := callAggregate(t, aggregateInput{Sources: srcs, Page: 99})
	if len(out.PerSource) != 0 {
		t.Errorf("out-of-range page must return no rollups, got %d", len(out.PerSource))
	}
	if !out.Truncated || !strings.Contains(out.Notice, "out of range") {
		t.Errorf("expected an out-of-range notice, got truncated=%v notice=%q", out.Truncated, out.Notice)
	}
	if out.Aggregate.Total != 7 {
		t.Errorf("aggregate total must stay complete (7) regardless of page, got %d", out.Aggregate.Total)
	}
}

// TestAggregate_PaginatesManySources: enough sources to exceed the response
// budget paginate the per-source list, but the aggregate total still reflects
// every source (the bounding guarantee, without losing the total).
func TestAggregate_PaginatesManySources(t *testing.T) {
	files := map[string][]byte{}
	var srcs []handle.Source
	body := readToolsFixture(t, "query-results.json")
	const n = 60
	for i := 0; i < n; i++ {
		name := "d" + strconv.Itoa(i) + ".json"
		files[name] = body
		srcs = append(srcs, handle.Source{Path: name})
	}
	writeRootFiles(t, files)
	_, out := callAggregate(t, aggregateInput{Sources: srcs})
	if !out.Truncated || out.NextPage == 0 {
		t.Fatalf("60 sources must paginate; got truncated=%v nextPage=%d perSource=%d", out.Truncated, out.NextPage, len(out.PerSource))
	}
	if len(out.PerSource) >= n {
		t.Errorf("a truncated page must hold fewer than all %d sources, got %d", n, len(out.PerSource))
	}
	if out.Aggregate.Total != n*5 {
		t.Errorf("aggregate total = %d, want %d (all sources counted despite paging)", out.Aggregate.Total, n*5)
	}
}

// TestAggregate_ScalesAcrossManyDocuments: the aggregate total scales with the
// document count without the caller summing anything — the motivating case.
func TestAggregate_ScalesAcrossManyDocuments(t *testing.T) {
	// 12 copies of the same 5-requirement doc → aggregate total 60, computed once.
	files := map[string][]byte{}
	var srcs []handle.Source
	body := readToolsFixture(t, "query-results.json")
	for i := 0; i < 12; i++ {
		name := "doc" + string(rune('a'+i)) + ".json"
		files[name] = body
		srcs = append(srcs, handle.Source{Path: name})
	}
	writeRootFiles(t, files)
	_, out := callAggregate(t, aggregateInput{Sources: srcs})
	if out.Aggregate.Total != 60 {
		t.Errorf("aggregate total over 12 docs = %d, want 60 (12 x 5)", out.Aggregate.Total)
	}
}
