package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ValidateResponseTokenCap is the serialized-token ceiling for an hdf_validate
// response (the concise 2k budget): a response that would exceed it drops
// validation errors with a notice.
const ValidateResponseTokenCap = respond.ConciseTokenBudget

// validateInput is the hdf_validate argument surface: a source (path/handle) or
// inline content, an optional docType, and one of three modes.
type validateInput struct {
	Source  *handle.Source `json:"source,omitempty" jsonschema:"the document to validate, as {path} or {handle}; omit when using content"`
	Content string         `json:"content,omitempty" jsonschema:"inline HDF document to validate, as an alternative to source"`
	DocType string         `json:"docType,omitempty" jsonschema:"optional document type to validate against in schema mode (e.g. hdf-results); defaults to the detected type"`
	Mode    string         `json:"mode" jsonschema:"validation mode: schema, checksums, or completeness"`
}

// validateError is one structured, line-numbered validation error.
type validateError struct {
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

// validateOutput is the hdf_validate result: a verdict, the mode, the detected
// (or requested) type, structured errors, and — for the evidence-verify modes —
// the agent-attributed override count across the package's results (§3).
type validateOutput struct {
	Valid              bool            `json:"valid"`
	Mode               string          `json:"mode"`
	DocType            string          `json:"docType,omitempty"`
	Errors             []validateError `json:"errors"`
	AgentOverrideCount int             `json:"agentOverrideCount,omitempty"`
	Notice             string          `json:"notice,omitempty"`
}

// errorValidateOutput is the structured output returned alongside a toolError or
// argError. errors is a required field; the SDK validates a tool's output even on
// an isError result, so an empty (non-nil) slice serializing as [] — rather than
// a nil slice serializing as null — keeps the result valid against any schema and
// prevents a validation failure from masking the taxonomy code (cf.
// errorComplianceOutput).
func errorValidateOutput() validateOutput {
	return validateOutput{Errors: []validateError{}}
}

// RegisterValidate registers the hdf_validate tool on the server.
func RegisterValidate(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_validate",
		Description: "Validate an HDF document in one of three modes: schema (JSON-Schema conformance for any of the eight document types, with line-numbered errors), checksums (verify an evidence package's referenced-file sha256 checksums), or completeness (verify every planned baseline has results). The checksums and completeness modes also report the agent-attributed override count across the package's results.",
		Annotations: appmcp.ReadOnly(),
	}, hdfValidate(ldr))
}

func hdfValidate(ldr *loader.Loader) sdkmcp.ToolHandlerFor[validateInput, validateOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in validateInput) (*sdkmcp.CallToolResult, validateOutput, error) {
		switch in.Mode {
		case "schema", "checksums", "completeness":
		default:
			return argError(fmt.Sprintf("unknown mode %q", in.Mode), "use mode schema, checksums, or completeness"), errorValidateOutput(), nil
		}

		content, baseDir, load, terr := resolveForValidate(in, ldr)
		if terr != nil {
			return toolError(terr), errorValidateOutput(), nil
		}

		out := validateOutput{Mode: in.Mode, Errors: []validateError{}}
		switch in.Mode {
		case "schema":
			validateSchema(&out, in.DocType, content, load)
		case "checksums":
			validateChecksums(&out, content, baseDir, load)
		case "completeness":
			validateCompleteness(&out, content, baseDir, load)
		}
		boundValidateResponse(&out)
		return nil, out, nil
	}
}

// resolveForValidate turns the source-or-content input into confined bytes, the
// base directory referenced files resolve against, and a loaded document. Inline
// content resolves referenced files against HDF_MCP_ROOT; a source resolves them
// against the source document's own directory.
func resolveForValidate(in validateInput, ldr *loader.Loader) ([]byte, string, *loader.Result, *mcperr.Error) {
	hasContent := in.Content != ""
	hasSource := in.Source != nil && (in.Source.Path != "" || in.Source.Handle != "")
	switch {
	case hasContent && hasSource:
		return nil, "", nil, mcperr.Arg("pass either source or content, not both", "pass exactly one of source or content")
	case hasContent:
		res, err := ldr.Load([]byte(in.Content))
		if err != nil {
			return nil, "", nil, sizeOrLoadError(err)
		}
		return []byte(in.Content), mcpRoot(), res, nil
	case hasSource:
		resolved, e := resolveSource(*in.Source, ldr, "source")
		if e != nil {
			return nil, "", nil, e
		}
		base := mcpRoot()
		if p, err := hdfutil.SafePath(mcpRoot(), resolved.Handle.Path); err == nil {
			base = filepath.Dir(p)
		}
		return resolved.Content, base, resolved.Load, nil
	default:
		return nil, "", nil, mcperr.New(mcperr.DocumentNotFound, "no source or content provided", nil).
			WithNextCall("pass source.path/source.handle or inline content")
	}
}

// validateSchema fills the verdict for schema mode. With no requested docType it
// reuses the loader's detected validation (line-numbered); with one it validates
// against that specific type.
func validateSchema(out *validateOutput, requestedDocType string, content []byte, load *loader.Result) {
	if requestedDocType == "" {
		out.DocType = load.DocType
		out.Valid = load.Valid
		out.Errors = fromLoaderErrors(load.Errors)
		if load.DocType == "" && len(out.Errors) == 0 {
			// Defensive: the loader already populates a distinguished message for
			// this case, so this rarely fires — share the same helper so the two
			// never drift (jobi.3 / D6).
			out.Errors = []validateError{{Message: loader.UnrecognizedMessage(content)}}
		}
		return
	}
	st, ok := schemaTypeForDoc(requestedDocType)
	if !ok {
		out.Errors = []validateError{{Message: "unknown document type " + requestedDocType}}
		return
	}
	out.DocType = string(st)
	vr := validators.Validate(content, st)
	out.Valid = vr.Valid
	out.Errors = lineNumberedErrors(vr, content)
}

// validateChecksums fills the verdict for checksums mode: verify each referenced
// file's sha256, and report the agent-override count across the package results.
func validateChecksums(out *validateOutput, content []byte, baseDir string, load *loader.Result) {
	contents, ok := requireEvidencePackage(out, content, load)
	if !ok {
		return
	}
	fetch := confinedFetchAt(baseDir)
	out.Valid = true
	for _, r := range hdfengine.VerifyChecksums(contents, fetch) {
		switch r.Status {
		case hdfengine.ChecksumMismatch:
			out.Valid = false
			out.Errors = append(out.Errors, validateError{Path: r.URI, Message: fmt.Sprintf("checksum mismatch: expected %s, got %s", r.Expected, r.Actual)})
		case hdfengine.ChecksumError:
			out.Valid = false
			out.Errors = append(out.Errors, validateError{Path: r.URI, Message: "cannot verify checksum: " + r.Error})
		}
	}
	out.AgentOverrideCount = aggregateAgentOverrides(contents, fetch)
}

// validateCompleteness fills the verdict for completeness mode: every planned
// baseline must be covered by a results document in the package.
func validateCompleteness(out *validateOutput, content []byte, baseDir string, load *loader.Result) {
	contents, ok := requireEvidencePackage(out, content, load)
	if !ok {
		return
	}
	planRef, _, _ := hdfengine.ParseEvidencePackage(content)
	fetch := confinedFetchAt(baseDir)
	out.AgentOverrideCount = aggregateAgentOverrides(contents, fetch)

	if planRef == "" {
		out.Errors = []validateError{{Message: "evidence package has no planRef; cannot check completeness"}}
		return
	}
	planData, ferr := fetch(planRef)
	if ferr != nil {
		out.Errors = []validateError{{Path: planRef, Message: "cannot read plan: " + ferr.Error()}}
		return
	}
	planned, perr := hdfengine.PlannedBaselineRefs(planData)
	if perr != nil {
		out.Errors = []validateError{{Path: planRef, Message: "cannot parse plan: " + perr.Error()}}
		return
	}
	var covered []string
	for _, c := range contents {
		if c.Type != "hdf-results" || c.URI == "" {
			continue
		}
		if data, rerr := fetch(c.URI); rerr == nil {
			if names, nerr := hdfengine.CoveredBaselineNames(data); nerr == nil {
				covered = append(covered, names...)
			}
		}
	}
	comp := hdfengine.Completeness(planned, covered)
	out.Valid = comp.Complete
	for _, m := range comp.Missing {
		out.Errors = append(out.Errors, validateError{Path: planRef, Message: "missing results for baseline " + m})
	}
}

// requireEvidencePackage confirms the document is an evidence package and parses
// its contents, or fills out with an explanatory invalid verdict and returns
// ok=false.
func requireEvidencePackage(out *validateOutput, content []byte, load *loader.Result) ([]hdfengine.EvidenceContent, bool) {
	out.DocType = load.DocType
	if load.DocType != string(validators.TypeEvidencePackage) {
		out.Errors = []validateError{{Message: "this mode requires an hdf-evidence-package document; detected " + docTypeLabel(load.DocType)}}
		return nil, false
	}
	_, contents, err := hdfengine.ParseEvidencePackage(content)
	if err != nil {
		out.Errors = []validateError{{Message: "cannot parse evidence package: " + err.Error()}}
		return nil, false
	}
	return contents, true
}

// aggregateAgentOverrides sums the agent-attributed override count across every
// hdf-results document referenced by the package (the §3 detective surface at
// the evidence-package level). Unreadable or unparseable results are skipped.
func aggregateAgentOverrides(contents []hdfengine.EvidenceContent, fetch hdfengine.FetchFunc) int {
	total := 0
	for _, c := range contents {
		if c.Type != "hdf-results" || c.URI == "" {
			continue
		}
		data, err := fetch(c.URI)
		if err != nil {
			continue
		}
		var r hdf.HDFResults
		if json.Unmarshal(data, &r) != nil {
			continue
		}
		total += hdfengine.AgentOverrideCount(r)
	}
	return total
}

// confinedFetchAt resolves a referenced URI relative to base, confined by
// SafePath so a traversal-escaping reference is rejected rather than read.
func confinedFetchAt(base string) hdfengine.FetchFunc {
	return func(uri string) ([]byte, error) {
		p, err := hdfutil.SafePath(base, uri)
		if err != nil {
			return nil, fmt.Errorf("referenced file %q is outside the evidence package root", uri)
		}
		fi, err := os.Stat(p)
		if err != nil {
			// Redact: a raw *PathError would carry the absolute confined path and
			// errno into the checksum result the client sees. Reference the
			// caller-relative uri only; log the cause for the operator.
			slog.Error("evidence fetch failed", "uri", uri, "cause", err)
			return nil, fmt.Errorf("referenced file %q could not be read", uri)
		}
		if limit := mcpMaxInputSize(); fi.Size() > limit {
			return nil, fmt.Errorf("referenced file %q is %d bytes, over the %d-byte limit", uri, fi.Size(), limit)
		}
		data, err := os.ReadFile(p) //nolint:gosec // confined by SafePath, size-guarded above
		if err != nil {
			slog.Error("evidence fetch failed", "uri", uri, "cause", err)
			return nil, fmt.Errorf("referenced file %q could not be read", uri)
		}
		return data, nil
	}
}

func fromLoaderErrors(errs []loader.ValidationError) []validateError {
	out := make([]validateError, 0, len(errs))
	for _, e := range errs {
		out = append(out, validateError{Path: e.Field, Line: e.Line, Message: e.Description})
	}
	return out
}

// lineNumberedErrors annotates a validators result with source line numbers via
// the same shared helpers the loader uses, capped at the loader's error budget.
func lineNumberedErrors(vr validators.ValidationResult, content []byte) []validateError {
	if vr.Valid {
		return []validateError{}
	}
	lineMap := hdfutil.JSONPathLineMap(content)
	out := make([]validateError, 0, len(vr.Errors))
	for i, e := range vr.Errors {
		if i >= loader.DefaultMaxErrors {
			break
		}
		out = append(out, validateError{
			Path:    e.Field,
			Line:    hdfutil.LookupLineNumber(lineMap, e.Field),
			Message: e.Description,
		})
	}
	return out
}

var validShortTypes = map[string]validators.SchemaType{
	"results":                  validators.TypeResults,
	"baseline":                 validators.TypeBaseline,
	"system":                   validators.TypeSystem,
	"plan":                     validators.TypePlan,
	"amendments":               validators.TypeAmendments,
	"evidence-package":         validators.TypeEvidencePackage,
	"comparison":               validators.TypeComparison,
	"requirement-change-event": validators.TypeRequirementChangeEvent,
}

func schemaTypeForDoc(s string) (validators.SchemaType, bool) {
	st, ok := validShortTypes[strings.TrimPrefix(s, "hdf-")]
	return st, ok
}

func docTypeLabel(dt string) string {
	if dt == "" {
		return "an unrecognized document"
	}
	return "hdf-" + dt
}

// boundValidateResponse enforces the 2k-token cap by dropping validation errors
// (the only unbounded field) to a bounded head and naming the remedy.
func boundValidateResponse(out *validateOutput) {
	if respond.EstimateTokens(mustJSON(out)) <= ValidateResponseTokenCap {
		return
	}
	total := len(out.Errors)
	lo, hi, best := 0, total, 0
	for lo <= hi {
		mid := (lo + hi) / 2
		trial := *out
		trial.Errors = out.Errors[:mid]
		trial.Notice = ""
		if respond.EstimateTokens(mustJSON(&trial)) <= ValidateResponseTokenCap {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	out.Errors = out.Errors[:best]
	out.Notice = fmt.Sprintf(
		"Response truncated to stay within the %d-token cap: showing %d of %d validation errors. Validate a specific docType to narrow, or fix the reported errors and re-run.",
		ValidateResponseTokenCap, best, total,
	)
}

// argError renders a malformed-argument isError result (a caller mistake, not a
// document-taxonomy error).
func argError(message, nextCall string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{
		IsError: true,
		Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: mustJSON(map[string]any{"error": message, "nextCall": nextCall})}},
	}
}
