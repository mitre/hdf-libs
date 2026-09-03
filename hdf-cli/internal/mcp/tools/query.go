package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// queryNarrowParam names the filters a truncation notice recommends tightening to
// shrink the result set. It deliberately does NOT mention limit — a smaller limit
// returns fewer rows, never more, so it is not a way to "see the rest".
const queryNarrowParam = "a status/severity/nist/id/search filter"

// queryInput is the hdf_query argument surface: a source, the requirement
// filters, the response controls (verbosity/limit/page), and an opt-in Fields
// projection that adds the bounded correlation set per row. Every filter is
// forwarded verbatim to the shared engine — the tool re-implements no matching.
type queryInput struct {
	Source    handle.Source `json:"source" jsonschema:"document as {path} or {handle}"`
	Status    []string      `json:"status,omitempty" jsonschema:"passed|failed|notApplicable|notReviewed|error (OR)"`
	Severity  []string      `json:"severity,omitempty" jsonschema:"critical|high|medium|low|none (OR)"`
	Impact    string        `json:"impact,omitempty" jsonschema:"comparison e.g. >0.5, =0"`
	CCI       []string      `json:"cci,omitempty"`
	NIST      []string      `json:"nist,omitempty" jsonschema:"NIST controls, globs allowed (AC-*)"`
	ID        string        `json:"id,omitempty" jsonschema:"requirement/STIG ID, GID, or group title"`
	Tag       []string      `json:"tag,omitempty" jsonschema:"key:value (OR)"`
	Search    string        `json:"search,omitempty" jsonschema:"text match over id/title/descriptions"`
	Baseline  string        `json:"baseline,omitempty" jsonschema:"baseline name, glob allowed"`
	Verbosity string        `json:"verbosity,omitempty" jsonschema:"concise (default) or full"`
	Limit     int           `json:"limit,omitempty" jsonschema:"cap on rows (0 = all)"`
	Page      int           `json:"page,omitempty" jsonschema:"0-based page when truncated"`
	Fields    []string      `json:"fields,omitempty" jsonschema:"opt-in correlation fields to add per row: cwe|cvss|affectedPackages|sourceLocation"`
}

// correlationProjectors is the bounded correlation set (bead-established): the
// normalized cross-source join keys that live on a requirement but that no read
// tool projects by default. Each extractor returns the value or nil, so an
// absent field is omitted from the row rather than serialized as null — a
// correlation consumer joins on presence. The set is exposed opt-in via
// queryInput.Fields and never widens the concise/full defaults.
var correlationProjectors = map[string]func(*hdf.EvaluatedRequirement) any{
	"cwe": func(r *hdf.EvaluatedRequirement) any {
		if len(r.Cwe) > 0 {
			return r.Cwe
		}
		return nil
	},
	"cvss": func(r *hdf.EvaluatedRequirement) any {
		if len(r.Cvss) > 0 {
			return r.Cvss
		}
		return nil
	},
	"affectedPackages": func(r *hdf.EvaluatedRequirement) any {
		if len(r.AffectedPackages) > 0 {
			return r.AffectedPackages
		}
		return nil
	},
	"sourceLocation": func(r *hdf.EvaluatedRequirement) any {
		if r.SourceLocation != nil {
			return r.SourceLocation
		}
		return nil
	},
}

// correlationFieldNames lists the allowed Fields values in a stable order, for
// the fail-loud validation error (the jsonschema tag is description-only — the
// reflector rejects enum tags — so the allowed set is enforced in the handler).
var correlationFieldNames = []string{"cwe", "cvss", "affectedPackages", "sourceLocation"}

// unknownCorrelationField returns the first Fields value that is not a known
// correlation field, so the handler can refuse it rather than silently ignore it.
func unknownCorrelationField(fields []string) (string, bool) {
	for _, f := range fields {
		if _, ok := correlationProjectors[f]; !ok {
			return f, true
		}
	}
	return "", false
}

// errorQueryOutput is the structured output returned alongside a toolError.
// requirements is a required field; the SDK validates a tool's output even on an
// isError result, so an empty (non-nil) slice serializing as [] — rather than a
// nil slice serializing as null — keeps the result valid against any schema and
// prevents a validation failure from masking the taxonomy code (cf.
// errorComplianceOutput).
func errorQueryOutput() queryOutput {
	return queryOutput{Requirements: []map[string]any{}}
}

// queryOutput is the hdf_query result envelope: the bounded requirement rows plus
// the pagination metadata, alongside the source handle and detected type.
type queryOutput struct {
	Handle              string           `json:"handle"`
	DocType             string           `json:"docType"`
	EngineSchemaVersion string           `json:"engineSchemaVersion"`
	Total               int              `json:"total"`
	Returned            int              `json:"returned"`
	Truncated           bool             `json:"truncated,omitempty"`
	NextPage            int              `json:"nextPage,omitempty"`
	Notice              string           `json:"notice,omitempty"`
	Requirements        []map[string]any `json:"requirements"`
}

// conciseRow is the default requirement projection: exactly id/title/status/
// severity/impact. None of these fields is omitempty — a zero impact or empty
// title must still appear so the field set is exactly five keys.
type conciseRow struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Status   string  `json:"status"`
	Severity string  `json:"severity"`
	Impact   float64 `json:"impact"`
}

// fullRow is the richer projection: the concise fields plus the originating
// baseline, the requirement's tags (NIST/CCI/STIG), and its descriptions.
type fullRow struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Status       string            `json:"status"`
	Severity     string            `json:"severity"`
	Impact       float64           `json:"impact"`
	Baseline     string            `json:"baseline"`
	Tags         map[string]any    `json:"tags,omitempty"`
	Descriptions []hdf.Description `json:"descriptions,omitempty"`
}

// queryDispatch maps a document type to the requirement collection it exposes to
// hdf_query, expressed as the HDFResults shape the shared engine filters. results
// and baseline are the only requirement-bearing types today. Registering another
// docType here is the single additive change that widens applicability when
// cross-document filtering lands (bead hdf-libs-yamp) — hdfQuery's body does not
// change. A docType absent from this map returns WRONG_DOC_TYPE pointing at
// hdf_inspect.
var queryDispatch = map[string]func(*loader.Result) hdf.HDFResults{
	"results": func(r *loader.Result) hdf.HDFResults {
		if r.Engine == nil || r.Engine.Results == nil {
			return hdf.HDFResults{}
		}
		return *r.Engine.Results
	},
	"baseline": func(r *loader.Result) hdf.HDFResults {
		if r.Engine == nil || r.Engine.Baseline == nil {
			return hdf.HDFResults{}
		}
		return baselineAsResults(r.Engine.Baseline)
	},
}

// RegisterQuery registers the hdf_query tool on the server. ldr is the shared
// document loader.
// queryToolDescription is what a model reads before choosing this tool, so it
// states the read surface's one deliberate blind spot (hdf-libs-uqhe.13):
// conversion keeps each scanner finding verbatim in the requirement's `code`,
// but no read tool projects it. Saying so costs a sentence; discovering it costs
// the agent a wrong or incomplete answer.
const queryToolDescription = "Filter requirements in an HDF results or baseline document. The only path to a " +
	"requirement collection; for other document types call hdf_inspect. " +
	"Returns normalized fields only: the scanner's original finding is preserved verbatim in each " +
	"requirement's `code`, but no read tool projects it, so a question about a tool-specific field " +
	"(a matcher, match provenance, a vendor extension) cannot be answered from this surface — read the source file instead."

func RegisterQuery(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_query",
		Description: queryToolDescription,
		Annotations: appmcp.ReadOnly(),
	}, hdfQuery(ldr))
}

// hdfQuery builds the typed handler. It resolves the source, dispatches on the
// detected document type (results/baseline are the only requirement-bearing
// types), delegates all matching to the shared engine, and returns a bounded,
// paginated result set.
func hdfQuery(ldr *loader.Loader) sdkmcp.ToolHandlerFor[queryInput, queryOutput] {
	return func(ctx context.Context, _ *sdkmcp.CallToolRequest, in queryInput) (*sdkmcp.CallToolResult, queryOutput, error) {
		if in.Impact != "" && !hdfengine.ValidImpactFilter(in.Impact) {
			return argError(fmt.Sprintf("invalid impact filter %q", in.Impact),
				"use a comparison like >0.5, >=0.7, <0.5, or =0"), errorQueryOutput(), nil
		}
		if f, ok := unknownCorrelationField(in.Fields); ok {
			return argError(fmt.Sprintf("unknown correlation field %q", f),
				fmt.Sprintf("fields accepts only: %s", strings.Join(correlationFieldNames, ", "))), errorQueryOutput(), nil
		}
		resolved, terr := resolveSource(in.Source, ldr, "source")
		if terr != nil {
			return toolError(terr), errorQueryOutput(), nil
		}
		encoded, err := handle.Encode(resolved.Handle)
		if err != nil {
			return nil, queryOutput{}, fmt.Errorf("encoding handle: %w", err)
		}

		toResults, ok := queryDispatch[resolved.Load.DocType]
		if !ok {
			return toolError(wrongDocTypeForQuery(resolved.Load.DocType)), errorQueryOutput(), nil
		}
		if !resolved.Load.Valid {
			e := mcperr.New(mcperr.SchemaInvalid,
				fmt.Sprintf("the document is %s but failed schema validation, so its requirements cannot be filtered", resolved.Load.DocType),
				map[string]any{"docType": resolved.Load.DocType})
			return toolError(e), errorQueryOutput(), nil
		}

		results := toResults(resolved.Load)
		matches := hdfengine.Filter(ctx, results, hdfengine.Options{
			Status: in.Status, Severity: in.Severity, Impact: in.Impact,
			CCI: in.CCI, NIST: in.NIST, ID: in.ID, Tag: in.Tag,
			Search: in.Search, Baseline: in.Baseline,
			Count:    true, // return every match; the tool applies limit + token paging
			StatusOf: effectiveStatus,
		})

		out := queryOutput{Handle: encoded, DocType: resolved.Load.DocType, EngineSchemaVersion: resolved.Handle.EngineSchemaVersion}
		buildQueryResponse(&out, results, matches, in.Verbosity, in.Limit, in.Page, in.Fields)
		return nil, out, nil
	}
}

// wrongDocTypeForQuery is the enforced other half of the hdf_inspect/hdf_query
// bright line: a document with no requirement collection is redirected to
// hdf_inspect.
func wrongDocTypeForQuery(docType string) *mcperr.Error {
	return mcperr.New(mcperr.WrongDocType,
		fmt.Sprintf("hdf_query filters requirements in results and baseline documents; a %s document carries no requirement collection", docType),
		map[string]any{"docType": docType}).
		WithNextCall("call hdf_inspect to view this document's structure (hdf_query is results/baseline only)")
}

// effectiveStatus resolves a requirement's status via the canonical ladder in
// status-determination.md (governing override → error roll-up → impact-0
// notApplicable → worst-wins roll-up). It returns the schema (effectiveStatus)
// vocabulary — the same vocabulary hdf_open's summary reports.
func effectiveStatus(control hdf.EvaluatedRequirement) string {
	return hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(control), time.Time{})
}

// countByEffectiveStatus counts a result set's requirements by their canonical
// effective status (the ladder in status-determination.md) — the single
// status convention every status-reporting MCP tool uses, so hdf_open,
// hdf_inspect, hdf_compliance and hdf_query all agree on one document. This is
// the effective-status seam; the raw CountControlsByStatusSeverity is
// deliberately NOT used by the MCP tools (it drives CLI threshold gating, whose
// separate correction is tracked apart from the read tools).
func countByEffectiveStatus(results hdf.HDFResults) *hdfengine.StatusCounts {
	return hdfengine.CountControlsByStatus(results, effectiveStatus)
}

// baselineAsResults projects a baseline document's requirements onto the
// HDFResults shape the engine filters, carrying the fields the engine and status
// resolver read (id, title, impact, tags, descriptions). A baseline requirement
// has no results or overrides, so it resolves to notReviewed (notApplicable at
// impact 0).
func baselineAsResults(b *hdf.HDFBaseline) hdf.HDFResults {
	reqs := make([]hdf.EvaluatedRequirement, 0, len(b.Requirements))
	for i := range b.Requirements {
		br := &b.Requirements[i]
		reqs = append(reqs, hdf.EvaluatedRequirement{
			ID:           br.ID,
			Title:        br.Title,
			Impact:       br.Impact,
			Tags:         br.Tags,
			Descriptions: br.Descriptions,
		})
	}
	return hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{{Name: b.Name, Requirements: reqs}}}
}

// buildQueryResponse projects matches to rows at the requested verbosity, applies
// the caller's limit, token-paginates the candidate rows, and fills the envelope
// (total is the true universe; a hidden remainder or extra pages set truncated).
func buildQueryResponse(out *queryOutput, results hdf.HDFResults, matches []hdfengine.Match, verbosity string, limit, page int, fields []string) {
	rows := projectRows(results, matches, verbosity, fields)
	out.Total = len(rows)

	candidates := rows
	limited := false
	if limit > 0 && limit < len(candidates) {
		candidates = candidates[:limit]
		limited = true
	}

	budget := respond.ConciseTokenBudget
	if verbosity == "full" {
		budget = respond.FullTokenBudget
	}
	// Measure the real envelope (fixed handle/metadata overhead counts), not the
	// rows alone, so pagination shares the exact budget the response is bound to.
	sizeOf := func(page []map[string]any) int {
		trial := *out
		trial.Requirements = page
		trial.Truncated = true
		trial.NextPage = 1
		return respond.EstimateTokens(mustJSON(&trial))
	}
	pages := respond.Paginate(candidates, budget, sizeOf)

	if page < 0 || page >= len(pages) {
		out.Requirements = []map[string]any{}
		out.Returned = 0
		out.Truncated = true
		out.Notice = fmt.Sprintf("page %d is out of range (%d page(s)); page 0 is the first.", page, len(pages))
		return
	}

	out.Requirements = pages[page]
	out.Returned = len(pages[page])

	morePages := len(pages) > 1
	if morePages || limited {
		out.Truncated = true
		if page+1 < len(pages) {
			out.NextPage = page + 1
		}
		out.Notice = queryTruncationNotice(out.Returned, out.Total, page, len(pages), limited)
	}
}

// queryTruncationNotice states what was withheld and the correct remedy for each
// reason: token-budget paging → fetch the next page; a caller limit → raise/remove
// it (paging cannot reach beyond the limit window); last page → revisit earlier
// pages. Tightening a filter shrinks the set in every case.
func queryTruncationNotice(returned, total, page, numPages int, limited bool) string {
	switch {
	case page+1 < numPages:
		return fmt.Sprintf(
			"Showing %d of %d requirements (page %d of %d). Fetch the next page with page=%d, or tighten %s to shrink the set.",
			returned, total, page, numPages, page+1, queryNarrowParam,
		)
	case limited:
		return fmt.Sprintf(
			"Showing %d of %d requirements (capped by limit). Raise or remove limit to see the rest — a larger result then pages with page=N; a smaller limit shows fewer, not more. Or tighten %s to shrink the set.",
			returned, total, queryNarrowParam,
		)
	default:
		return fmt.Sprintf(
			"Showing %d of %d requirements (page %d of %d, last page). Revisit earlier pages with page=0..%d, or tighten %s to shrink the set.",
			returned, total, page, numPages, numPages-1, queryNarrowParam,
		)
	}
}

// projectRows converts engine matches into concise or full rows. Full rows join
// back to the source requirement (by baseline+id) for tags and descriptions.
// projectRows returns rows as map[string]any so the derived output schema is a
// concrete object (additionalProperties) rather than a bare boolean, which MCP
// clients reject under items. Rows are built from the typed conciseRow/fullRow
// structs and marshalled via structToMap so their json tags (exact concise keys,
// omitempty full extras) remain authoritative.
func projectRows(results hdf.HDFResults, matches []hdfengine.Match, verbosity string, fields []string) []map[string]any {
	full := verbosity == "full"
	// The source-requirement index is needed for full's tags/descriptions and for
	// any opt-in correlation fields; build it once when either is requested.
	var index map[string]*hdf.EvaluatedRequirement
	if full || len(fields) > 0 {
		index = indexRequirements(results)
	}
	rows := make([]map[string]any, 0, len(matches))
	for _, m := range matches {
		var row map[string]any
		if full {
			fr := fullRow{ID: m.ID, Title: m.Title, Status: m.Status, Severity: m.Severity, Impact: m.Impact, Baseline: m.Baseline}
			if src := index[requirementKey(m.Baseline, m.ID)]; src != nil {
				fr.Tags = src.Tags
				fr.Descriptions = src.Descriptions
			}
			row = structToMap(fr)
		} else {
			row = structToMap(conciseRow{ID: m.ID, Title: m.Title, Status: m.Status, Severity: m.Severity, Impact: m.Impact})
		}
		if len(fields) > 0 {
			if src := index[requirementKey(m.Baseline, m.ID)]; src != nil {
				for _, f := range fields {
					if v := correlationProjectors[f](src); v != nil {
						row[f] = v
					}
				}
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func indexRequirements(results hdf.HDFResults) map[string]*hdf.EvaluatedRequirement {
	index := map[string]*hdf.EvaluatedRequirement{}
	for i := range results.Baselines {
		b := &results.Baselines[i]
		for j := range b.Requirements {
			r := &b.Requirements[j]
			index[requirementKey(b.Name, r.ID)] = r
		}
	}
	return index
}

func requirementKey(baseline, id string) string {
	return baseline + "\x00" + id
}
