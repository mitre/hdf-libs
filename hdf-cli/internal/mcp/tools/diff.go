package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	diff "github.com/mitre/hdf-libs/hdf-diff/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// diffNarrowParam names the response controls a truncation notice recommends.
const diffNarrowParam = "verbosity=concise or page=N"

// diffInput is the hdf_diff argument surface: two sources, a comparison mode, and
// the response/emission controls.
type diffInput struct {
	From      handle.Source `json:"from" jsonschema:"the 'before' document as {path} or {handle}"`
	To        handle.Source `json:"to" jsonschema:"the 'after' document as {path} or {handle}"`
	Mode      string        `json:"mode,omitempty" jsonschema:"temporal (results across time, default) or system-drift (system docs)"`
	Verbosity string        `json:"verbosity,omitempty" jsonschema:"concise (default) or full"`
	Page      int           `json:"page,omitempty" jsonschema:"0-based page when the change list is truncated"`
	Output    string        `json:"output,omitempty" jsonschema:"path under HDF_MCP_ROOT to write the hdf-comparison document"`
	DryRun    bool          `json:"dryRun,omitempty" jsonschema:"with output set, preview the write (return the summary + sha256, write no file)"`
	Overwrite bool          `json:"overwrite,omitempty" jsonschema:"replace an existing output file (default false)"`
}

// diffOutput is the hdf_diff result: the comparison summary, a bounded change
// list, the two source handles, and — when output is given — the emitted
// hdf-comparison artifact's path, hash, and validity.
type diffOutput struct {
	FromHandle     string                 `json:"fromHandle"`
	ToHandle       string                 `json:"toHandle"`
	Mode           string                 `json:"mode"`
	Summary        diff.ComparisonSummary `json:"summary"`
	Changes        []map[string]any       `json:"changes"`
	Total          int                    `json:"total"`
	Returned       int                    `json:"returned"`
	Truncated      bool                   `json:"truncated,omitempty"`
	NextPage       int                    `json:"nextPage,omitempty"`
	Notice         string                 `json:"notice,omitempty"`
	OutputPath     string                 `json:"outputPath,omitempty"`
	Sha256         string                 `json:"sha256,omitempty"`
	Valid          bool                   `json:"valid,omitempty"`
	WritesDisabled bool                   `json:"writesDisabled,omitempty"`
}

// errorDiffOutput is the structured output returned alongside a toolError.
// changes is a required field; the SDK validates a tool's output even on an
// isError result, so an empty (non-nil) slice serializing as [] — rather than a
// nil slice serializing as null — keeps the result valid against any schema and
// prevents a validation failure from masking the taxonomy code (cf.
// errorComplianceOutput).
func errorDiffOutput() diffOutput {
	return diffOutput{Changes: []map[string]any{}}
}

// RegisterDiff registers the hdf_diff tool on the server.
func RegisterDiff(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name: "hdf_diff",
		Description: "Compare two HDF documents: temporal (results across time) or system-drift (system " +
			"documents). Returns a summary and a bounded change list; with output set, writes an " +
			"hdf-comparison document.",
		Annotations: appmcp.ReadOnly(),
	}, hdfDiff(ldr))
}

func hdfDiff(ldr *loader.Loader) sdkmcp.ToolHandlerFor[diffInput, diffOutput] {
	return func(ctx context.Context, _ *sdkmcp.CallToolRequest, in diffInput) (*sdkmcp.CallToolResult, diffOutput, error) {
		mode := in.Mode
		if mode == "" {
			mode = "temporal"
		}
		if mode != "temporal" && mode != "system-drift" {
			return argError(fmt.Sprintf("unknown mode %q", mode), "use mode = temporal or system-drift"), errorDiffOutput(), nil
		}

		from, terr := resolveSource(in.From, ldr, "from")
		if terr != nil {
			return toolError(terr), errorDiffOutput(), nil
		}
		to, terr := resolveSource(in.To, ldr, "to")
		if terr != nil {
			return toolError(terr), errorDiffOutput(), nil
		}
		fromH, err := handle.Encode(from.Handle)
		if err != nil {
			return nil, diffOutput{}, fmt.Errorf("encoding from handle: %w", err)
		}
		toH, err := handle.Encode(to.Handle)
		if err != nil {
			return nil, diffOutput{}, fmt.Errorf("encoding to handle: %w", err)
		}

		comp, terr := computeComparison(ctx, mode, from, to)
		if terr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, diffOutput{}, ctxErr // client cancelled — propagate, don't mislabel as SchemaInvalid
			}
			return toolError(terr), errorDiffOutput(), nil
		}
		// The shared engine stamps a wall-clock generation Timestamp — correct for
		// the CLI's "generated at", but it makes the MCP's content-addressed diff
		// artifact hash differently for identical inputs across a one-second tick,
		// violating the no-wall-clock determinism contract (ADR-0007 §10). Drop it:
		// timestamp is optional in hdf-comparison and the artifact is anchored by
		// its sources/handles, not its generation time.
		comp.Timestamp = ""

		out := diffOutput{FromHandle: fromH, ToHandle: toH, Mode: mode, Summary: comp.Summary}

		changes := projectChanges(comp, mode, in.Verbosity)
		buildDiffResponse(&out, changes, in.Verbosity, in.Page)

		// Emit last so a write-model notice (dry-run / WRITES_DISABLED) is appended
		// to — not clobbered by — any truncation notice buildDiffResponse set.
		if in.Output != "" {
			// Never write the comparison over either input document, even with overwrite.
			if terr := refuseOverwritingInput(in.Output, from.Handle.Path); terr != nil {
				return toolError(terr), errorDiffOutput(), nil
			}
			if terr := refuseOverwritingInput(in.Output, to.Handle.Path); terr != nil {
				return toolError(terr), errorDiffOutput(), nil
			}
			if terr := emitComparison(&out, comp, in.Output, in.DryRun, in.Overwrite); terr != nil {
				return toolError(terr), errorDiffOutput(), nil
			}
		}
		return nil, out, nil
	}
}

// computeComparison delegates to the shared engine: temporal compares two results
// documents, system-drift two system documents. A document of the wrong type for
// the mode returns WRONG_DOC_TYPE; a schema-invalid one returns SCHEMA_INVALID.
func computeComparison(ctx context.Context, mode string, from, to *Resolved) (diff.HdfComparison, *mcperr.Error) {
	switch mode {
	case "temporal":
		if terr := requireDocType(from, "results", mode); terr != nil {
			return diff.HdfComparison{}, terr
		}
		if terr := requireDocType(to, "results", mode); terr != nil {
			return diff.HdfComparison{}, terr
		}
		comp, err := diff.DiffHdf(ctx, *from.Load.Engine.Results, []hdf.HDFResults{*to.Load.Engine.Results},
			diff.Options{ComparisonMode: diff.ModeTemporal})
		if err != nil {
			return diff.HdfComparison{}, mcperr.New(mcperr.SchemaInvalid, "diff failed: "+err.Error(), nil)
		}
		return comp, nil
	default: // system-drift
		if terr := requireDocType(from, "system", mode); terr != nil {
			return diff.HdfComparison{}, terr
		}
		if terr := requireDocType(to, "system", mode); terr != nil {
			return diff.HdfComparison{}, terr
		}
		var oldSys, newSys map[string]any
		if err := json.Unmarshal(from.Content, &oldSys); err != nil {
			return diff.HdfComparison{}, mcperr.New(mcperr.SchemaInvalid, "from system document did not parse", nil)
		}
		if err := json.Unmarshal(to.Content, &newSys); err != nil {
			return diff.HdfComparison{}, mcperr.New(mcperr.SchemaInvalid, "to system document did not parse", nil)
		}
		comp, err := diff.DiffSystems(ctx, oldSys, newSys)
		if err != nil {
			return diff.HdfComparison{}, mcperr.New(mcperr.SchemaInvalid, "system diff failed: "+err.Error(), nil)
		}
		return comp, nil
	}
}

// requireDocType enforces the mode's expected document type, pointing a mismatch
// at the right mode or hdf_inspect.
func requireDocType(r *Resolved, want, mode string) *mcperr.Error {
	if !r.Load.Valid {
		return mcperr.New(mcperr.SchemaInvalid,
			fmt.Sprintf("the document is %s but failed schema validation, so it cannot be diffed", r.Load.DocType),
			map[string]any{"docType": r.Load.DocType})
	}
	if r.Load.DocType != want {
		other := "system-drift"
		if mode == "system-drift" {
			other = "temporal"
		}
		return mcperr.New(mcperr.WrongDocType,
			fmt.Sprintf("%s mode compares %s documents; got %s", mode, want, r.Load.DocType),
			map[string]any{"docType": r.Load.DocType, "mode": mode}).
			WithNextCall(fmt.Sprintf("pass %s documents, or switch to mode=%s (or call hdf_inspect)", want, other))
	}
	return nil
}

// emitComparison marshals the engine comparison (already schema-shaped), writes
// it to the confined output path, and records the path, hash, and schema validity.
func emitComparison(out *diffOutput, comp diff.HdfComparison, output string, dryRun, overwrite bool) *mcperr.Error {
	docBytes, err := json.MarshalIndent(comp, "", "  ")
	if err != nil {
		return mcperr.New(mcperr.SchemaInvalid, "could not serialize the comparison", nil)
	}
	// Validate and hash the comparison regardless of whether it is written, so a
	// dry-run/writes-disabled preview still reports what would land on disk.
	out.Valid = validators.Validate(docBytes, validators.TypeComparison).Valid
	sum := sha256.Sum256(docBytes)
	out.Sha256 = hex.EncodeToString(sum[:])

	// The write itself goes through the one shared write model (gate + dry_run +
	// confinement) — no direct filesystem write in the tool.
	writtenPath, notice, terr := writeArtifact(output, dryRun, overwrite, docBytes)
	if terr != nil {
		return terr
	}
	out.OutputPath = writtenPath
	if notice != "" {
		out.Notice = appendNotice(out.Notice, notice)
		out.WritesDisabled = strings.Contains(notice, "WRITES_DISABLED")
	}
	return nil
}

// appendNotice joins a write-model notice onto any existing (e.g. truncation)
// notice without clobbering it.
func appendNotice(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + " " + add
}

// changeRow projections. Concise carries the identifying + state fields; full
// adds impacts, field changes, and metadata. changeReasons pass through verbatim,
// so v3.5.0 additions (dispositionChanged, effectiveImpactChanged) surface
// unchanged rather than being dropped.
type temporalConcise struct {
	ID            string                `json:"id"`
	State         diff.RequirementState `json:"state"`
	ChangeReasons []diff.ChangeReason   `json:"changeReasons"`
	OldStatus     string                `json:"oldStatus,omitempty"`
	NewStatus     string                `json:"newStatus,omitempty"`
}

type temporalFull struct {
	temporalConcise
	Title        string             `json:"title,omitempty"`
	Baseline     string             `json:"baseline,omitempty"`
	OldImpact    *float64           `json:"oldImpact,omitempty"`
	NewImpact    *float64           `json:"newImpact,omitempty"`
	FieldChanges []diff.FieldChange `json:"fieldChanges,omitempty"`
}

type componentConcise struct {
	Name  string                `json:"name"`
	State diff.RequirementState `json:"state"`
}

type componentFull struct {
	componentConcise
	FieldChanges []diff.FieldChange `json:"fieldChanges,omitempty"`
}

// projectChanges builds the bounded-eligible change list for the mode. Only
// actually-changed entries are listed (unchanged counts live in the summary).
// projectChanges returns rows as map[string]any (via structToMap of the typed row
// structs) so the derived output schema is a concrete object rather than a bare
// boolean under items, which MCP clients reject.
func projectChanges(comp diff.HdfComparison, mode, verbosity string) []map[string]any {
	full := verbosity == "full"
	var rows []map[string]any
	if mode == "temporal" {
		for i := range comp.RequirementDiffs {
			rd := comp.RequirementDiffs[i]
			if rd.State == diff.StateUnchanged {
				continue
			}
			concise := temporalConcise{
				ID: rd.ID, State: rd.State, ChangeReasons: rd.ChangeReasons,
				OldStatus: rd.OldEffectiveStatus, NewStatus: rd.NewEffectiveStatus,
			}
			if concise.ChangeReasons == nil {
				concise.ChangeReasons = []diff.ChangeReason{}
			}
			if full {
				rows = append(rows, structToMap(temporalFull{
					temporalConcise: concise, Title: rd.Title, Baseline: rd.Baseline,
					OldImpact: rd.OldImpact, NewImpact: rd.NewImpact, FieldChanges: rd.FieldChanges,
				}))
			} else {
				rows = append(rows, structToMap(concise))
			}
		}
		return rows
	}
	for i := range comp.ComponentDiffs {
		cd := comp.ComponentDiffs[i]
		if cd.State == diff.StateUnchanged {
			continue
		}
		concise := componentConcise{Name: cd.Name, State: cd.State}
		if full {
			rows = append(rows, structToMap(componentFull{componentConcise: concise, FieldChanges: cd.FieldChanges}))
		} else {
			rows = append(rows, structToMap(concise))
		}
	}
	return rows
}

// buildDiffResponse token-bounds the change list to the verbosity budget and
// fills the pagination envelope.
func buildDiffResponse(out *diffOutput, rows []map[string]any, verbosity string, page int) {
	out.Total = len(rows)
	budget := respond.ConciseTokenBudget
	if verbosity == "full" {
		budget = respond.FullTokenBudget
	}
	// Measure the real envelope (the summary sibling + handle overhead counts),
	// not the change rows alone, via the shared paginator.
	sizeOf := func(page []map[string]any) int {
		trial := *out
		trial.Changes = page
		trial.Truncated = true
		trial.NextPage = 1
		return respond.EstimateTokens(mustJSON(&trial))
	}
	pages := respond.Paginate(rows, budget, sizeOf)
	if page < 0 || page >= len(pages) {
		out.Changes = []map[string]any{}
		out.Returned = 0
		out.Truncated = true
		out.Notice = fmt.Sprintf("page %d is out of range (%d page(s)); page 0 is the first.", page, len(pages))
		return
	}
	out.Changes = pages[page]
	out.Returned = len(pages[page])
	if len(pages) > 1 {
		out.Truncated = true
		if page+1 < len(pages) {
			out.NextPage = page + 1
		}
		out.Notice = fmt.Sprintf(
			"Change list spans %d pages within the %s budget; showing page %d of %d (%d of %d changes). Narrow with %s.",
			len(pages), verbosityLabel(verbosity), page, len(pages), out.Returned, out.Total, diffNarrowParam)
	}
}
