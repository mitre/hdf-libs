package tools

import (
	"context"
	"fmt"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// aggregateInput is the hdf_aggregate argument surface: several sources to roll
// up together plus the same status/severity/nist filters hdf_query accepts,
// which narrow the counted set. It returns counts only — never per-requirement
// rows — so a cross-document call can never become an unbounded merged result.
type aggregateInput struct {
	Sources  []handle.Source `json:"sources" jsonschema:"documents to aggregate, each {path} or {handle}"`
	Status   []string        `json:"status,omitempty" jsonschema:"passed|failed|notApplicable|notReviewed|error (OR)"`
	Severity []string        `json:"severity,omitempty" jsonschema:"critical|high|medium|low|none (OR)"`
	NIST     []string        `json:"nist,omitempty" jsonschema:"NIST controls, globs allowed (AC-*)"`
	Page     int             `json:"page,omitempty" jsonschema:"0-based page when perSource is truncated"`
}

// aggregateSourceRollup is one document's contribution: its detected type, the
// count of requirements matching the filter, its compliance percentage, and the
// status×severity breakdown (same shape and effective-status convention as
// hdf_compliance).
type aggregateSourceRollup struct {
	Index      int                       `json:"index"`
	Source     string                    `json:"source,omitempty"`
	DocType    string                    `json:"docType"`
	Total      int                       `json:"total"`
	Compliance float64                   `json:"compliance"`
	Counts     map[string]map[string]int `json:"counts"`
}

// aggregateFailure records a source that could not be aggregated (not found,
// schema-invalid, or not a requirement-bearing document), so a partial failure
// is explicit rather than silently dropping a document from the total.
type aggregateFailure struct {
	Index  int    `json:"index"`
	Source string `json:"source,omitempty"`
	Error  string `json:"error"`
}

// aggregateTotals is the server-computed roll-up across every successfully-loaded
// source. It always reflects ALL such sources, even when perSource is paginated —
// the total is the reason this tool exists, so it never depends on the page.
type aggregateTotals struct {
	Total      int                       `json:"total"`
	Compliance float64                   `json:"compliance"`
	Counts     map[string]map[string]int `json:"counts"`
}

// aggregateOutput is the hdf_aggregate result: the (paginated) per-source
// rollups, the all-source aggregate, and any per-source load failures.
type aggregateOutput struct {
	SourceCount int                     `json:"sourceCount"`
	PerSource   []aggregateSourceRollup `json:"perSource"`
	Aggregate   aggregateTotals         `json:"aggregate"`
	Failures    []aggregateFailure      `json:"failures,omitempty"`
	Truncated   bool                    `json:"truncated,omitempty"`
	NextPage    int                     `json:"nextPage,omitempty"`
	Notice      string                  `json:"notice,omitempty"`
}

// errorAggregateOutput is the structured output returned alongside a toolError.
// The SDK validates output even on an isError result, so perSource is a non-nil
// slice and the aggregate carries a non-nil (all-zero) counts map.
func errorAggregateOutput() aggregateOutput {
	return aggregateOutput{
		PerSource: []aggregateSourceRollup{},
		Aggregate: aggregateTotals{Counts: countsToNestedInt(&hdfengine.StatusCounts{})},
	}
}

// RegisterAggregate registers the hdf_aggregate tool on the server.
func RegisterAggregate(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name: "hdf_aggregate",
		Description: "Roll up status/severity counts across MULTIPLE HDF results or baseline documents in one call: " +
			"per-source counts plus a server-computed total and compliance, so an agent never carries partial sums " +
			"across turns. Optional status/severity/nist filters narrow the counted set. Counts only — never " +
			"per-requirement rows. A source that fails to load is reported in failures[] and the rest still aggregate. " +
			"For a single document use hdf_compliance; for requirement rows use hdf_query.",
		Annotations: appmcp.ReadOnly(),
	}, hdfAggregate(ldr))
}

// hdfAggregate builds the typed handler. It resolves each source independently,
// counts the filter-matching requirements per source by effective status (the
// shared convention every status tool uses), sums them server-side, and returns
// a bounded per-source list plus the all-source aggregate. A source that fails
// to load is recorded in failures[] rather than failing the whole call.
func hdfAggregate(ldr *loader.Loader) sdkmcp.ToolHandlerFor[aggregateInput, aggregateOutput] {
	return func(ctx context.Context, _ *sdkmcp.CallToolRequest, in aggregateInput) (*sdkmcp.CallToolResult, aggregateOutput, error) {
		if len(in.Sources) == 0 {
			return argError("aggregate needs at least one source",
				"pass sources[] with one or more {path} or {handle} documents"), errorAggregateOutput(), nil
		}

		combined := hdf.HDFResults{}
		perSource := make([]aggregateSourceRollup, 0, len(in.Sources))
		var failures []aggregateFailure
		total := 0

		for i := range in.Sources {
			src := in.Sources[i]
			label := src.Path
			resolved, terr := resolveSource(src, ldr, "sources")
			if terr != nil {
				failures = append(failures, aggregateFailure{Index: i, Source: label, Error: terr.Message})
				continue
			}
			if label == "" {
				label = resolved.Handle.Path
			}
			toResults, ok := queryDispatch[resolved.Load.DocType]
			if !ok {
				failures = append(failures, aggregateFailure{Index: i, Source: label,
					Error: fmt.Sprintf("a %s document has no requirements to aggregate (results and baseline only)", resolved.Load.DocType)})
				continue
			}
			if !resolved.Load.Valid {
				failures = append(failures, aggregateFailure{Index: i, Source: label,
					Error: fmt.Sprintf("the document is %s but failed schema validation, so it cannot be aggregated", resolved.Load.DocType)})
				continue
			}
			results := toResults(resolved.Load)
			matches := hdfengine.Filter(ctx, results, hdfengine.Options{
				Status: in.Status, Severity: in.Severity, NIST: in.NIST,
				Count: true, StatusOf: effectiveStatus,
			})
			filtered := filterResultsToMatches(results, matches)
			counts := countByEffectiveStatus(filtered)
			perSource = append(perSource, aggregateSourceRollup{
				Index: i, Source: label, DocType: resolved.Load.DocType,
				Total: len(matches), Compliance: hdfengine.CalculateCompliance(counts),
				Counts: countsToNestedInt(counts),
			})
			total += len(matches)
			combined.Baselines = append(combined.Baselines, filtered.Baselines...)
		}

		aggCounts := countByEffectiveStatus(combined)
		out := aggregateOutput{
			SourceCount: len(perSource),
			Aggregate: aggregateTotals{
				Total: total, Compliance: hdfengine.CalculateCompliance(aggCounts),
				Counts: countsToNestedInt(aggCounts),
			},
			Failures: failures,
		}
		boundAggregate(&out, perSource, in.Page)
		return nil, out, nil
	}
}

// filterResultsToMatches projects a results document down to the requirements the
// engine matched, preserving baseline grouping, so the shared effective-status
// counter can be reused on the filtered set (no re-implemented counting).
func filterResultsToMatches(results hdf.HDFResults, matches []hdfengine.Match) hdf.HDFResults {
	keep := make(map[string]bool, len(matches))
	for _, m := range matches {
		keep[requirementKey(m.Baseline, m.ID)] = true
	}
	out := hdf.HDFResults{}
	for i := range results.Baselines {
		b := results.Baselines[i]
		var reqs []hdf.EvaluatedRequirement
		for j := range b.Requirements {
			if keep[requirementKey(b.Name, b.Requirements[j].ID)] {
				reqs = append(reqs, b.Requirements[j])
			}
		}
		if len(reqs) > 0 {
			nb := b
			nb.Requirements = reqs
			out.Baselines = append(out.Baselines, nb)
		}
	}
	return out
}

// boundAggregate paginates the per-source list against the concise token budget
// so a large document set cannot produce an unbounded response, while the
// aggregate totals (already computed over every source) are attached unchanged on
// every page. It mirrors respond.Paginate's greedy fill for the typed rollups.
func boundAggregate(out *aggregateOutput, all []aggregateSourceRollup, page int) {
	sizeOf := func(entries []aggregateSourceRollup) int {
		trial := *out
		trial.PerSource = entries
		trial.Truncated = true
		trial.NextPage = 1
		return respond.EstimateTokens(mustJSON(&trial))
	}
	var pages [][]aggregateSourceRollup
	i := 0
	for i < len(all) {
		var cur []aggregateSourceRollup
		for i < len(all) {
			next := append(append([]aggregateSourceRollup(nil), cur...), all[i])
			if sizeOf(next) > respond.ConciseTokenBudget && len(cur) > 0 {
				break
			}
			cur = next
			i++
		}
		pages = append(pages, cur)
	}
	if len(pages) == 0 {
		pages = append(pages, nil)
	}
	if page < 0 || page >= len(pages) {
		out.PerSource = []aggregateSourceRollup{}
		out.Truncated = true
		out.Notice = fmt.Sprintf("page %d is out of range (%d page(s)); page 0 is the first. The aggregate totals reflect all sources.", page, len(pages))
		return
	}
	out.PerSource = pages[page]
	if len(pages) > 1 {
		out.Truncated = true
		if page+1 < len(pages) {
			out.NextPage = page + 1
		}
		out.Notice = fmt.Sprintf(
			"Showing %d of %d sources (page %d of %d); fetch the next with page=%d. The aggregate totals already reflect ALL sources regardless of paging.",
			len(pages[page]), len(all), page, len(pages), page+1)
	}
}
