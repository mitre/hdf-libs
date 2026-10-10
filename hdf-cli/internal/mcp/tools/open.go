package tools

import (
	"context"
	"encoding/json"
	"fmt"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// OpenResponseTokenCap is the serialized-token ceiling for an hdf_open response
// (1k tokens): a response that would exceed it is truncated with a notice.
const OpenResponseTokenCap = 1000

// openInput is the hdf_open argument surface: a source that is a path or a
// handle. The SDK derives the input JSON schema from this struct.
type openInput struct {
	Source handle.Source `json:"source" jsonschema:"the document to open, as {path} or {handle}"`
}

// openOutput is the hdf_open result: a minted handle, detected type/version,
// validity, degraded-read errors, and a type-specific headline summary.
type openOutput struct {
	Handle              string            `json:"handle"`
	DocType             string            `json:"docType"`
	EngineSchemaVersion string            `json:"engineSchemaVersion"`
	Valid               bool              `json:"valid"`
	ValidationErrors    []validationError `json:"validationErrors,omitempty"`
	Summary             map[string]any    `json:"summary,omitempty"`
	Notice              string            `json:"notice,omitempty"`
}

type validationError struct {
	Line        int    `json:"line"`
	Field       string `json:"field,omitempty"`
	Description string `json:"description"`
}

// RegisterOpen registers the hdf_open tool on the server. ldr is the shared
// document loader (byte-bounded cache + degraded reads).
func RegisterOpen(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_open",
		Description: "Open an HDF document: detect its type, validate it, mint a reusable handle, and return a headline summary. Optional first hop for a multi-question session; a one-shot path call also works.",
		Annotations: appmcp.ReadOnly(),
	}, hdfOpen(ldr))
}

// hdfOpen builds the typed handler. It resolves the source, degrades on invalid
// input rather than hard-failing, assembles the type-specific summary, and
// token-bounds the response.
func hdfOpen(ldr *loader.Loader) sdkmcp.ToolHandlerFor[openInput, openOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in openInput) (*sdkmcp.CallToolResult, openOutput, error) {
		resolved, terr := resolveSource(in.Source, ldr, "source")
		if terr != nil {
			return toolError(terr), openOutput{}, nil
		}

		encoded, err := handle.Encode(resolved.Handle)
		if err != nil {
			// Encoding an all-scalar handle cannot fail in practice; an internal
			// serialization failure is a genuine error, not a recoverable taxonomy
			// code, so surface it as a Go error rather than a tool result.
			return nil, openOutput{}, fmt.Errorf("encoding handle: %w", err)
		}

		out := openOutput{
			Handle:              encoded,
			DocType:             resolved.Load.DocType,
			EngineSchemaVersion: resolved.Handle.EngineSchemaVersion,
			Valid:               resolved.Load.Valid,
		}

		if !resolved.Load.Valid {
			// Degraded read: carry the detected type + line-numbered errors, no hard fail.
			out.ValidationErrors = toValidationErrors(resolved.Load.Errors)
		} else {
			out.Summary = summarize(resolved.Load.Engine, resolved.Content)
		}

		boundOpenResponse(&out)
		return textResult(fmt.Sprintf("hdf_open: %s (schema %s), valid=%t. Handle + summary in structuredContent.",
			out.DocType, out.EngineSchemaVersion, out.Valid)), out, nil
	}
}

// summarize builds the type-specific headline summary for a valid document. The engine core
// struct-parses results and baseline; system and plan are summarized by a generic walk of
// the raw content (the loader does not struct-parse them).
//
// It returns a map, not the typed struct: `any` on the output field reflects to a bare
// `true` schema — "anything" — which is weaker than the map it would replace. The typed
// structs below are the contract source instead.
func summarize(lr *hdfengine.LoadResult, content []byte) map[string]any {
	switch lr.DocType {
	case "results":
		return resultsSummary(lr.Results)
	case "baseline":
		return baselineSummary(lr.Baseline)
	case "system":
		return systemSummary(content)
	case "plan":
		return planSummary(content)
	default:
		return nil
	}
}

// systemSummary reports component count by type from the raw system document.
func systemSummary(content []byte) map[string]any {
	var doc struct {
		Components []struct {
			Type string `json:"type"`
		} `json:"components"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil
	}
	byType := map[string]int{}
	for _, c := range doc.Components {
		byType[c.Type]++
	}
	return structToMap(systemOpenSummary{ComponentCount: len(doc.Components), ComponentByType: byType})
}

// planSummary reports the assessment count from the raw plan document.
func planSummary(content []byte) map[string]any {
	var doc struct {
		Assessments []json.RawMessage `json:"assessments"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil
	}
	return structToMap(planOpenSummary{AssessmentCount: len(doc.Assessments)})
}

func resultsSummary(r *hdf.HDFResults) map[string]any {
	if r == nil {
		return nil
	}
	reqCount := 0
	for i := range r.Baselines {
		reqCount += len(r.Baselines[i].Requirements)
	}
	counts := countByEffectiveStatus(*r)
	return structToMap(resultsOpenSummary{
		BaselineCount:    len(r.Baselines),
		RequirementCount: reqCount,
		StatusBreakdown: resultsStatusBreakdown{
			Passed:        counts.Passed.Total,
			Failed:        counts.Failed.Total,
			NotApplicable: counts.NoImpact.Total,
			NotReviewed:   counts.Skipped.Total,
			Error:         counts.Error.Total,
		},
	})
}

func baselineSummary(b *hdf.HDFBaseline) map[string]any {
	if b == nil {
		return nil
	}
	return structToMap(baselineOpenSummary{RequirementCount: len(b.Requirements)})
}

// The per-docType open summaries, typed rather than built as map[string]any.
//
// Each has a fixed key set, so a struct describes it exactly and the contract golden can
// carry a real shape instead of an untyped blob — which is what ADR-0008 prerequisite (b)
// needs for an HTTP response body. The four document types with NO summary are recorded in
// summarylessDocTypes below rather than left to a silent nil.

// resultsOpenSummary is the hdf-results summary: counts plus the effective-status breakdown.
type resultsOpenSummary struct {
	BaselineCount    int                    `json:"baselineCount"`
	RequirementCount int                    `json:"requirementCount"`
	StatusBreakdown  resultsStatusBreakdown `json:"statusBreakdown"`
}

// resultsStatusBreakdown counts requirements by effective status. The field tags are the
// Result_Status vocabulary; they are the wire contract, so they live here once.
type resultsStatusBreakdown struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	NotApplicable int `json:"notApplicable"`
	NotReviewed   int `json:"notReviewed"`
	Error         int `json:"error"`
}

// baselineOpenSummary is the hdf-baseline summary.
type baselineOpenSummary struct {
	RequirementCount int `json:"requirementCount"`
}

// systemOpenSummary is the hdf-system summary. ComponentByType is keyed by component type,
// which is open-ended by design (the schema admits an x- custom namespace), so it stays a
// map and the contract describes it as one.
type systemOpenSummary struct {
	ComponentCount  int            `json:"componentCount"`
	ComponentByType map[string]int `json:"componentByType"`
}

// planOpenSummary is the hdf-plan summary.
type planOpenSummary struct {
	AssessmentCount int `json:"assessmentCount"`
}

// summarylessDocTypes are the document types hdf_open returns no summary for, with the
// reason. Recorded rather than absent: a reader of the contract can tell "nothing to
// summarise yet" apart from "someone forgot", and the test below fails if a document type
// is neither summarised nor listed here.
var summarylessDocTypes = map[string]string{
	"comparison":               "hdf_diff already returns the comparison summary; opening one adds nothing",
	"amendments":               "an overrides list has no aggregate worth a summary line; hdf_query reports applied overrides",
	"evidence-package":         "contents are references, counted by hdf_validate mode=checksums",
	"requirement-change-event": "a change event is a single unit; its payload IS the summary",
}

func toValidationErrors(errs []loader.ValidationError) []validationError {
	out := make([]validationError, 0, len(errs))
	for _, e := range errs {
		out = append(out, validationError{Line: e.Line, Field: e.Field, Description: e.Description})
	}
	return out
}

// boundOpenResponse enforces the 1k-token cap: if the serialized response is
// over budget, it drops the validationErrors[] (the only unbounded part) to a
// bounded head and names the narrowing next call rather than dropping silently.
func boundOpenResponse(out *openOutput) {
	if respond.EstimateTokens(mustJSON(out)) <= OpenResponseTokenCap {
		return
	}
	total := len(out.ValidationErrors)
	// Binary-search the largest prefix of errors that keeps the response in budget.
	lo, hi, best := 0, total, 0
	for lo <= hi {
		mid := (lo + hi) / 2
		trial := *out
		trial.ValidationErrors = out.ValidationErrors[:mid]
		trial.Notice = ""
		if respond.EstimateTokens(mustJSON(&trial)) <= OpenResponseTokenCap {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	out.ValidationErrors = out.ValidationErrors[:best]
	out.Notice = fmt.Sprintf(
		"Response truncated to stay within the %d-token cap: showing %d of %d validation errors. Call hdf_validate for the full line-numbered error list.",
		OpenResponseTokenCap, best, total,
	)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// structToMap converts a value to a map[string]any via a JSON round-trip so the
// value's json tags (field names, omitempty) stay authoritative. Map-typed output
// fields reflect to an object schema with additionalProperties, which MCP clients
// accept — unlike the bare boolean schema an `any`/`[]any` field would produce
// under items/properties.
func structToMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return map[string]any{}
	}
	return m
}

// toolError renders a taxonomy error as an isError tool result carrying the
// structured payload (code, message, nextCall). A caller-argument mistake
// (mcperr.Arg) carries no document code, so it is rendered through the shared
// argError shape instead — one render path, no code overloading.
func toolError(e *mcperr.Error) *sdkmcp.CallToolResult {
	if e.IsArgError() {
		return argError(e.Message, e.NextCall)
	}
	tr := e.AsToolResult()
	return &sdkmcp.CallToolResult{
		IsError: true,
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: mustJSON(tr)}},
	}
}
