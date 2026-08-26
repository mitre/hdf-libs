package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-diff/go/v3/amend"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// applyAmendmentInput is the hdf_apply_amendment argument surface: a results
// document and an amendments document (each a {path} or {handle}), plus the
// shared write-model controls. The output is always a NEW results file — the
// results input is never overwritten.
type applyAmendmentInput struct {
	Results    handle.Source `json:"results" jsonschema:"the HDF results document to apply amendments to, as {path} or {handle}"`
	Amendments handle.Source `json:"amendments" jsonschema:"the hdf-amendments document to apply, as {path} or {handle}"`
	Output     string        `json:"output,omitempty" jsonschema:"path under HDF_MCP_ROOT to write the applied results (a NEW file; the results input is never overwritten)"`
	DryRun     bool          `json:"dryRun,omitempty" jsonschema:"with output set, preview the write (return the delta, write no file)"`
	Overwrite  bool          `json:"overwrite,omitempty" jsonschema:"replace an existing output file (default false)"`
}

// projectedCompliance is the before/after effective-compliance percentage the
// applied amendments produce.
type projectedCompliance struct {
	Before float64 `json:"before"`
	After  float64 `json:"after"`
}

// applyAmendmentOutput is summary-only — never the applied document body.
type applyAmendmentOutput struct {
	OutputPath              string              `json:"outputPath,omitempty"`
	Handle                  string              `json:"handle"`
	ProjectedCompliance     projectedCompliance `json:"projectedCompliance"`
	ChangedRequirementCount int                 `json:"changedRequirementCount"`
	Sha256                  string              `json:"sha256"`
	Valid                   bool                `json:"valid"`
	WritesDisabled          bool                `json:"writesDisabled,omitempty"`
	Notice                  string              `json:"notice,omitempty"`
}

// RegisterApplyAmendment registers the hdf_apply_amendment tool on the server.
func RegisterApplyAmendment(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_apply_amendment",
		Description: "Apply an hdf-amendments document to an HDF results document, deterministically producing a NEW results file with effectiveStatus/effectiveImpact/disposition computed — the results input is NEVER overwritten. The applied file retains statusOverrides[] with appliedBy, so attribution and agent-override counts survive on the results artifact itself. Returns the before/after projected compliance, the changed-requirement count, and a reusable handle — never the document body. Writes under the shared write model (dry_run returns the delta without writing; a writes-disabled deployment returns a preview). Output that does not validate as hdf-results is refused.",
		Annotations: appmcp.Writing(false, true),
	}, hdfApplyAmendment(ldr))
}

func hdfApplyAmendment(ldr *loader.Loader) sdkmcp.ToolHandlerFor[applyAmendmentInput, applyAmendmentOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in applyAmendmentInput) (*sdkmcp.CallToolResult, applyAmendmentOutput, error) {
		results, terr := resolveTyped(in.Results, "results", ldr)
		if terr != nil {
			return toolError(terr), applyAmendmentOutput{}, nil
		}
		amendments, terr := resolveTyped(in.Amendments, "amendments", ldr)
		if terr != nil {
			return toolError(terr), applyAmendmentOutput{}, nil
		}

		// Never overwrite the results input, in ANY mode: refuse an output that
		// resolves to the same file up front (the write model would otherwise
		// happily clobber it on an enabled write).
		if werr := refuseOverwritingInput(in.Output, results.Handle.Path); werr != nil {
			return toolError(werr), applyAmendmentOutput{}, nil
		}

		merged, terr := applyMerge(results.Content, amendments.Content)
		if terr != nil {
			return toolError(terr), applyAmendmentOutput{}, nil
		}
		if terr := refuseInvalidResults(merged); terr != nil {
			return toolError(terr), applyAmendmentOutput{}, nil
		}

		out, terr := applySummary(results.Content, merged)
		if terr != nil {
			return toolError(terr), applyAmendmentOutput{}, nil
		}

		writtenPath, notice, werr := writeArtifact(in.Output, in.DryRun, in.Overwrite, merged)
		if werr != nil {
			return toolError(werr), applyAmendmentOutput{}, nil
		}
		out.OutputPath = writtenPath
		if notice != "" {
			out.Notice = notice
			out.WritesDisabled = strings.Contains(notice, "WRITES_DISABLED")
		}

		// Register the merged document in the content cache and mint the handle
		// against the ACTUAL written path — empty when nothing was written, which
		// routes resolution to the in-memory cache so apply's output chains into
		// compliance/inspect with writes disabled (jobi.1 / D1).
		_, _ = ldr.Load(merged)
		encoded, herr := handle.Encode(handle.Compute(writtenPath, merged, "results", hdfengine.Version()))
		if herr != nil {
			return nil, applyAmendmentOutput{}, fmt.Errorf("encoding handle: %w", herr)
		}
		out.Handle = encoded
		return nil, out, nil
	}
}

// applyMerge runs the shared, deterministic amend.MergeAmendments and funnels
// its error through the taxonomy (so the handler never checks a bare error and
// returns nil in the Go-error slot).
func applyMerge(results, amendments []byte) ([]byte, *mcperr.Error) {
	merged, err := amend.MergeAmendments(results, amendments)
	if err != nil {
		return nil, mcperr.New(mcperr.SchemaInvalid, "applying the amendments failed: "+err.Error(), nil).
			WithNextCall("verify the amendments target requirement IDs in the results and are not an incomplete draft")
	}
	return merged, nil
}

// resolveTyped resolves a source and enforces the expected document type.
func resolveTyped(src handle.Source, want string, ldr *loader.Loader) (*Resolved, *mcperr.Error) {
	res, terr := resolveSource(src, ldr, want)
	if terr != nil {
		return nil, terr
	}
	if res.Load.DocType != want {
		return nil, mcperr.New(mcperr.WrongDocType,
			fmt.Sprintf("expected an hdf-%s document, got %q", want, res.Load.DocType), nil).
			WithNextCall("pass an hdf-" + want + " document in this slot")
	}
	return res, nil
}

// refuseOverwritingInput rejects an output path that resolves to the same
// confined file as an input document being read — a produced document is always
// a new file, never written in place over its own input (which would destroy the
// input mid-read). Shared by hdf_apply_amendment (results input) and hdf_convert
// (source input).
func refuseOverwritingInput(output, inputPath string) *mcperr.Error {
	if output == "" || inputPath == "" {
		return nil
	}
	// Compare only when both confine cleanly; an unconfinable output falls
	// through to the write model, which reports PATH_DENIED.
	outConfined, oerr := hdfutil.SafePath(mcpRoot(), output)
	inConfined, ierr := hdfutil.SafePath(mcpRoot(), inputPath)
	if oerr == nil && ierr == nil && sameConfinedFile(outConfined, inConfined) {
		return mcperr.New(mcperr.PathDenied, "output would overwrite the input document being read", map[string]any{"path": output}).
			WithNextCall("choose a different output path — the input is never overwritten in place")
	}
	return nil
}

// sameConfinedFile reports whether two confined paths resolve to the same file.
// Lexical equality is a cheap pre-check but NOT authoritative: SafePath validates
// a symlink for containment without expanding it, so an in-root symlink or
// hardlink alias of the input has a different path string yet the same underlying
// file. Device+inode identity is the authority — os.Stat follows symlinks, so
// os.SameFile catches both alias kinds. A not-yet-created output has nothing to
// alias, so the lexical result stands.
func sameConfinedFile(a, b string) bool {
	if a == b {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// applySummary computes the before/after compliance delta and the changed-
// requirement count over the shared effective-status path (no re-implementation).
func applySummary(before, after []byte) (applyAmendmentOutput, *mcperr.Error) {
	var b, a hdf.HDFResults
	if err := json.Unmarshal(before, &b); err != nil {
		return applyAmendmentOutput{}, mcperr.New(mcperr.SchemaInvalid, "could not parse the results input: "+err.Error(), nil)
	}
	if err := json.Unmarshal(after, &a); err != nil {
		return applyAmendmentOutput{}, mcperr.New(mcperr.SchemaInvalid, "could not parse the applied results: "+err.Error(), nil)
	}
	sum := sha256.Sum256(after)
	return applyAmendmentOutput{
		ProjectedCompliance: projectedCompliance{
			Before: hdfengine.CalculateCompliance(countByEffectiveStatus(b)),
			After:  hdfengine.CalculateCompliance(countByEffectiveStatus(a)),
		},
		ChangedRequirementCount: changedRequirementCount(b, a),
		Sha256:                  hex.EncodeToString(sum[:]),
		Valid:                   true,
	}, nil
}

// changedRequirementCount counts requirements whose effective status changed
// between the before and after result sets, keyed by baseline name + requirement
// ID, using the shared effectiveStatus resolver.
func changedRequirementCount(before, after hdf.HDFResults) int {
	beforeStatus := effectiveStatusByKey(before)
	changed := 0
	for _, baseline := range after.Baselines {
		for i := range baseline.Requirements {
			key := baseline.Name + "\x00" + baseline.Requirements[i].ID
			if prev, ok := beforeStatus[key]; !ok || prev != effectiveStatus(baseline.Requirements[i]) {
				changed++
			}
		}
	}
	return changed
}

func effectiveStatusByKey(results hdf.HDFResults) map[string]string {
	m := make(map[string]string)
	for _, baseline := range results.Baselines {
		for i := range baseline.Requirements {
			m[baseline.Name+"\x00"+baseline.Requirements[i].ID] = effectiveStatus(baseline.Requirements[i])
		}
	}
	return m
}
