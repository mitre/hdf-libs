package tools

import (
	"context"
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
	Content string         `json:"content,omitempty" jsonschema:"inline HDF document to validate, as an alternative to source; an evidence package's references are not resolved from inline content, so pass source.path to verify them"`
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
		Description: "Validate an HDF document in one of three modes: schema (JSON-Schema conformance for any of the eight document types, with line-numbered errors), checksums (verify an evidence package's referenced-file checksums, each under the algorithm its entry records), or completeness (verify every planned baseline has results). The checksums and completeness modes also report the agent-attributed override count across the package's results.",
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

		content, fetch, load, terr := resolveForValidate(in, ldr)
		if terr != nil {
			return toolError(terr), errorValidateOutput(), nil
		}

		out := validateOutput{Mode: in.Mode, Errors: []validateError{}}
		switch in.Mode {
		case "schema":
			validateSchema(&out, in.DocType, content, load)
		case "checksums":
			validateChecksums(&out, content, fetch, load)
		case "completeness":
			validateCompleteness(&out, content, fetch, load)
		}
		boundValidateResponse(&out)
		return textResult(fmt.Sprintf("hdf_validate (%s): valid=%t, %d error(s). Detail in structuredContent.",
			out.Mode, out.Valid, len(out.Errors))), out, nil
	}
}

// resolveForValidate turns the source-or-content input into confined bytes, the
// fetcher that referenced files are read through, and a loaded document. A
// content reference means a path relative to the package document's own
// directory, so the rule is whether the document HAS a directory: one read from a
// file resolves against filepath.Dir of its own path, and one that never existed
// as a file resolves nothing. Two inputs reach the second case — inline content,
// and a handle with an empty path, which marks a document authored in this session
// and never written. Keying on the input field instead missed the second and left
// it resolving against the MCP root. Deciding it here is also what keeps the
// checksums and completeness modes from diverging.
func resolveForValidate(in validateInput, ldr *loader.Loader) ([]byte, hdfengine.FetchFunc, *loader.Result, *mcperr.Error) {
	hasContent := in.Content != ""
	hasSource := in.Source != nil && (in.Source.Path != "" || in.Source.Handle != "")
	switch {
	case hasContent && hasSource:
		return nil, nil, nil, mcperr.Arg("pass either source or content, not both", "pass exactly one of source or content")
	case hasContent:
		res, err := ldr.Load([]byte(in.Content))
		if err != nil {
			return nil, nil, nil, sizeOrLoadError(err)
		}
		return []byte(in.Content), unresolvableFetch(noLocationInline), res, nil
	case hasSource:
		resolved, e := resolveSource(*in.Source, ldr, "source")
		if e != nil {
			return nil, nil, nil, e
		}
		// Tested directly rather than inferred from SafePath refusing an empty
		// path: the condition is that the document HAS no location, and reading it
		// off an error both hid a real path failure and made the fallback to the
		// MCP root look deliberate.
		if resolved.Handle.Path == "" {
			return resolved.Content, unresolvableFetch(noLocationAuthored), resolved.Load, nil
		}
		// RETAINED THOUGH UNREACHABLE TODAY: both resolvers confine the path before
		// returning (resolvePath, resolveHandle), so this fires only if containment
		// changes between their check and this one. It fails closed rather than
		// falling back to the MCP root, which is the substitution this card removed —
		// deleting it would quietly restore that fallback for whatever reaches here.
		p, perr := hdfutil.SafePath(mcpRoot(), resolved.Handle.Path)
		if perr != nil {
			return nil, nil, nil, mcperr.New(mcperr.PathDenied,
				"the document's own path resolves outside HDF_MCP_ROOT",
				map[string]any{"path": resolved.Handle.Path})
		}
		return resolved.Content, confinedFetchAt(filepath.Dir(p)), resolved.Load, nil
	default:
		return nil, nil, nil, mcperr.New(mcperr.DocumentNotFound, "no source or content provided", nil).
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
// file against the algorithm its own entry records, and report the agent-override
// count across the package results.
func validateChecksums(out *validateOutput, content []byte, fetch hdfengine.FetchFunc, load *loader.Result) {
	contents, ok := requireEvidencePackage(out, content, load)
	if !ok {
		return
	}
	out.Valid = true
	var unverifiable []string
	for _, r := range hdfengine.VerifyChecksums(contents, fetch) {
		switch r.Status {
		case hdfengine.ChecksumMismatch:
			out.Valid = false
			out.Errors = append(out.Errors, validateError{Path: r.URI, Message: fmt.Sprintf("checksum mismatch: expected %s, got %s", r.Expected, r.Actual)})
		case hdfengine.ChecksumError:
			out.Valid = false
			out.Errors = append(out.Errors, validateError{Path: r.URI, Message: "cannot verify checksum: " + r.Error})
		case hdfengine.ChecksumUnsupported:
			// NOT an error and NOT invalid: the recorded algorithm is one this build
			// cannot compute, so the bytes may be intact. Every algorithm Hash_Algorithm
			// admits is computed now, so this is reachable only for an OFF-SCHEMA
			// algorithm. Reported in the notice so the caller knows a
			// checksum went unchecked — falling through to no case at all would have
			// reported an unverified entry as verified.
			// The algorithm is named alongside the entry: a caller told a checksum went
			// unverified cannot act on that without knowing which algorithm it was.
			unverifiable = append(unverifiable, r.URI+" ("+r.Algorithm+")")
		case hdfengine.ChecksumMatch, hdfengine.ChecksumSkipped:
			// A match needs no error, and a skipped entry declared no checksum to verify.
		}
	}
	if len(unverifiable) > 0 {
		out.Notice = appendNotice(out.Notice, fmt.Sprintf(
			"%d checksum(s) record an algorithm this build cannot compute and were not verified: %s",
			len(unverifiable), strings.Join(unverifiable, ", ")))
	}
	out.AgentOverrideCount = hdfengine.AgentOverridesInPackage(contents, fetch)
}

// validateCompleteness fills the verdict for completeness mode: every planned
// baseline must be covered by a results document in the package.
func validateCompleteness(out *validateOutput, content []byte, fetch hdfengine.FetchFunc, load *loader.Result) {
	contents, ok := requireEvidencePackage(out, content, load)
	if !ok {
		return
	}
	planRef, _, _ := hdfengine.ParseEvidencePackage(content)
	out.AgentOverrideCount = hdfengine.AgentOverridesInPackage(contents, fetch)

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
	comp := hdfengine.Completeness(planned, hdfengine.CoveredBaselinesInPackage(contents, fetch))
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

// The two ways a document can arrive with no location of its own, as the reason
// clause of the refusal below. Written out rather than derived, because the
// remedy is the same but the situation a caller has to recognize is not.
const (
	noLocationInline   = "inline content has no package directory"
	noLocationAuthored = "a handle with no path is a document that was never written to a file, so it has no package directory"
)

// unresolvableFetch is the fetcher for a document that carries no location: the
// bytes never existed as a file, so there is no package directory and every
// candidate base is a guess. Resolving against HDF_MCP_ROOT would read a
// same-named file the package never referenced — reporting drift in a document
// the operator never named, or, where that file happened to match, reporting
// verified bytes nobody read. Refusing is reported per entry by the callers: a
// checksum error, and an unreadable planRef in completeness mode.
func unresolvableFetch(why string) hdfengine.FetchFunc {
	return func(uri string) ([]byte, error) {
		return nil, fmt.Errorf("referenced file %q cannot be resolved: %s to resolve it against; "+
			"pass source.path to a package file on disk instead", uri, why)
	}
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

// validShortTypes is the docType→schema lookup, derived from the engine's
// enumeration so a new document type lands in one place.
var validShortTypes = func() map[string]validators.SchemaType {
	known := hdfengine.KnownTypes()
	m := make(map[string]validators.SchemaType, len(known))
	for _, k := range known {
		m[k] = validators.SchemaType(k)
	}
	return m
}()

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
