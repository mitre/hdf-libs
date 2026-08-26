package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"
	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/registry/all" // register fingerprints for auto-detect
	convreg "github.com/mitre/hdf-libs/hdf-converters/v3/registry/convert"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Stamp a converter version so produced documents carry a valid generator.version
// even in a bare MCP/test process (the CLI sets this too; last writer wins, both
// valid).
func init() { convreg.SetVersion(hdfengine.Version()) }

// convertInput is the hdf_convert argument surface: raw tool output (path or
// inline), an optional source format, an optional confined output path, and the
// label/componentId threading.
type convertInput struct {
	Source      *handle.Source    `json:"source,omitempty" jsonschema:"the raw tool-output file as {path}"`
	Content     string            `json:"content,omitempty" jsonschema:"inline raw tool output"`
	From        string            `json:"from,omitempty" jsonschema:"source format (e.g. nessus, gosec); auto-detected when omitted"`
	Output      string            `json:"output,omitempty" jsonschema:"path under HDF_MCP_ROOT to write"`
	DryRun      bool              `json:"dryRun,omitempty" jsonschema:"preview the write without writing"`
	Overwrite   bool              `json:"overwrite,omitempty" jsonschema:"replace an existing output file"`
	Labels      map[string]string `json:"labels,omitempty" jsonschema:"labels for output components"`
	ComponentID string            `json:"componentId,omitempty" jsonschema:"componentId for output components"`

	// Batch mode (mutually exclusive with source/content): convert many files in
	// one call, auto-detecting each. Provide sources[] and/or a directory.
	Sources   []handle.Source `json:"sources,omitempty" jsonschema:"batch: tool-output files, each {path}"`
	Directory string          `json:"directory,omitempty" jsonschema:"batch: a dir under HDF_MCP_ROOT to convert"`
	Pattern   string          `json:"pattern,omitempty" jsonschema:"batch: glob for directory (default all files)"`
	OutputDir string          `json:"outputDir,omitempty" jsonschema:"batch: dir under HDF_MCP_ROOT for outputs"`
	FailFast  bool            `json:"failFast,omitempty" jsonschema:"batch: stop at the first failure"`
}

// fileConvertSummary is one entry in a batch response: summary-only, never a
// document body. A failed file carries error+code and valid:false; the batch
// still completes the others unless failFast is set.
type fileConvertSummary struct {
	InputPath        string `json:"inputPath"`
	OutputPath       string `json:"outputPath,omitempty"`
	Handle           string `json:"handle,omitempty"`
	DocType          string `json:"docType,omitempty"`
	BaselineCount    int    `json:"baselineCount,omitempty"`
	RequirementCount int    `json:"requirementCount,omitempty"`
	Sha256           string `json:"sha256,omitempty"`
	Valid            bool   `json:"valid"`
	Error            string `json:"error,omitempty"`
	Code             string `json:"code,omitempty"`
}

// toMap renders a batch entry as the wire map the response carries. omitempty is
// applied by hand (native Go values, no JSON round-trip) so a failed entry omits
// the success fields and vice versa.
func (s fileConvertSummary) toMap() map[string]any {
	m := map[string]any{"inputPath": s.InputPath, "valid": s.Valid}
	if s.OutputPath != "" {
		m["outputPath"] = s.OutputPath
	}
	if s.Handle != "" {
		m["handle"] = s.Handle
	}
	if s.DocType != "" {
		m["docType"] = s.DocType
	}
	if s.BaselineCount != 0 {
		m["baselineCount"] = s.BaselineCount
	}
	if s.RequirementCount != 0 {
		m["requirementCount"] = s.RequirementCount
	}
	if s.Sha256 != "" {
		m["sha256"] = s.Sha256
	}
	if s.Error != "" {
		m["error"] = s.Error
	}
	if s.Code != "" {
		m["code"] = s.Code
	}
	return m
}

// convertOutput is summary-only — NEVER the converted document body (routinely
// megabytes). It carries the counts, integrity hash, validity, a reusable handle,
// and the write-model result.
type convertOutput struct {
	OutputPath       string `json:"outputPath,omitempty"`
	Handle           string `json:"handle"`
	DocType          string `json:"docType"`
	BaselineCount    int    `json:"baselineCount"`
	RequirementCount int    `json:"requirementCount"`
	Sha256           string `json:"sha256"`
	Valid            bool   `json:"valid"`
	WritesDisabled   bool   `json:"writesDisabled,omitempty"`
	Notice           string `json:"notice,omitempty"`

	// Batch mode: one summary per input file. Empty in single-file mode. Typed as
	// []map[string]any (not a concrete item schema) to keep hdf_convert under the
	// per-tool token ceiling — the same fidelity-vs-budget trade hdf_query and
	// hdf_diff make for their row collections (ADR-0007 Known constraints / lj0g.3).
	Batch     []map[string]any `json:"batch,omitempty"`
	Truncated bool             `json:"truncated,omitempty"`
}

// RegisterConvert registers the hdf_convert tool on the server.
func RegisterConvert(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_convert",
		Description: "Convert source security-tool output into an HDF results document and return a compact SUMMARY plus a reusable handle — never the converted body. from is auto-detected (incl NDJSON) when omitted. Batch mode: pass sources[] and/or directory to convert many files in one call, returning a per-file summary array (continue-past-failure unless failFast). With output/outputDir it writes under the shared write model (dryRun previews; writes-disabled returns a preview). Output failing hdf-results validation is refused.",
		Annotations: appmcp.Writing(false, true),
	}, hdfConvert(ldr))
}

func hdfConvert(ldr *loader.Loader) sdkmcp.ToolHandlerFor[convertInput, convertOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in convertInput) (*sdkmcp.CallToolResult, convertOutput, error) {
		if len(in.Sources) > 0 || in.Directory != "" {
			return hdfConvertBatch(ldr, in)
		}
		data, terr := rawInput(in.Source, in.Content)
		if terr != nil {
			return toolError(terr), convertOutput{}, nil
		}
		conv, terr := resolveConverter(in.From, data)
		if terr != nil {
			return toolError(terr), convertOutput{}, nil
		}

		hdfBytes, terr := convertAndPostProcess(conv, data, in.Labels, in.ComponentID)
		if terr != nil {
			return toolError(terr), convertOutput{}, nil
		}

		// Refuse schema-invalid output — never write or hand back a bad artifact (§13).
		if terr := refuseInvalidResults(hdfBytes); terr != nil {
			return toolError(terr), convertOutput{}, nil
		}

		out := convertSummary(hdfBytes)

		// Never overwrite the source being converted, even with overwrite set —
		// that would destroy the input mid-read (hdf_convert source=x output=x).
		if in.Source != nil {
			if terr := refuseOverwritingInput(in.Output, in.Source.Path); terr != nil {
				return toolError(terr), convertOutput{}, nil
			}
		}

		writtenPath, notice, werr := writeArtifact(in.Output, in.DryRun, in.Overwrite, hdfBytes)
		if werr != nil {
			return toolError(werr), convertOutput{}, nil
		}
		out.OutputPath = writtenPath
		if notice != "" {
			out.Notice = notice
			out.WritesDisabled = strings.Contains(notice, "WRITES_DISABLED")
		}

		// Register the converted document in the content cache and mint the handle
		// against the ACTUAL written path — empty when nothing was written, which
		// routes resolution to the in-memory cache so the handle is consumable
		// even with writes disabled (jobi.1 / D1).
		_, _ = ldr.Load(hdfBytes)
		encoded, herr := handle.Encode(handle.Compute(writtenPath, hdfBytes, "results", hdfengine.Version()))
		if herr != nil {
			return nil, convertOutput{}, fmt.Errorf("encoding handle: %w", herr)
		}
		out.Handle = encoded
		return nil, out, nil
	}
}

// hdfConvertBatch converts many source files in one call: it auto-detects each
// file's format via the shared registry, writes one HDF file per input under the
// confined output directory (shared write model), and returns a token-bounded
// per-file summary array — never a document body. Continue-past-failure is the
// default; failFast aborts on the first failed file. The whole batch carries a
// single write notice (dry-run / writes-disabled), not one per file.
func hdfConvertBatch(ldr *loader.Loader, in convertInput) (*sdkmcp.CallToolResult, convertOutput, error) {
	if in.Content != "" || (in.Source != nil && (in.Source.Path != "" || in.Source.Handle != "")) {
		return toolError(mcperr.Arg(
			"batch inputs (sources/directory) cannot be combined with single-file source/content",
			"pass either sources/directory for a batch, or source/content for a single file")), convertOutput{}, nil
	}
	paths, terr := enumerateBatchPaths(in)
	if terr != nil {
		return toolError(terr), convertOutput{}, nil
	}

	// Decide the write mode once so the batch carries a single notice, not one
	// per file. Conversion itself is pure and always runs.
	shouldWrite := in.OutputDir != "" && !in.DryRun && writesEnabled()
	if shouldWrite {
		if terr := prepareOutputDir(in.OutputDir); terr != nil {
			return toolError(terr), convertOutput{}, nil
		}
	}

	var out convertOutput
	for _, rel := range paths {
		entry := convertOneFile(ldr, rel, in, shouldWrite)
		out.Batch = append(out.Batch, entry.toMap())
		if in.FailFast && entry.Code != "" {
			break
		}
	}

	if in.OutputDir != "" {
		switch {
		case in.DryRun:
			out.Notice = dryRunNotice
		case !writesEnabled():
			out.Notice = writesDisabledNotice
			out.WritesDisabled = true
		}
	}
	boundBatchResponse(&out)
	return nil, out, nil
}

// prepareOutputDir confines the batch output directory to HDF_MCP_ROOT and
// creates it (mirroring the CLI's bulk-convert MkdirAll) so per-file writes land.
func prepareOutputDir(dir string) *mcperr.Error {
	confinedDir, err := hdfutil.SafePath(mcpRoot(), dir)
	if err != nil {
		return mcperr.New(mcperr.PathDenied, "outputDir resolves outside HDF_MCP_ROOT", map[string]any{"path": dir})
	}
	if err := os.MkdirAll(confinedDir, 0o750); err != nil {
		return redactFileErr(mcperr.WriteFailed, "could not create the output directory", dir, err)
	}
	return nil
}

// enumerateBatchPaths resolves the batch input into a deterministic, deduplicated
// list of HDF_MCP_ROOT-relative paths. A path escaping the root is retained so
// convertOneFile can report PATH_DENIED per file; a handle in sources[] or an
// empty match set is a caller mistake (arg error).
func enumerateBatchPaths(in convertInput) ([]string, *mcperr.Error) {
	seen := map[string]bool{}
	var rels []string
	add := func(rel string) {
		key := rel
		if confined, err := hdfutil.SafePath(mcpRoot(), rel); err == nil {
			key = confined
		}
		if seen[key] {
			return
		}
		seen[key] = true
		rels = append(rels, rel)
	}

	for _, s := range in.Sources {
		if s.Handle != "" {
			return nil, mcperr.Arg("batch sources take raw tool-output paths, not handles", "pass each source as {path}")
		}
		if s.Path == "" {
			return nil, mcperr.Arg("a batch source has neither path nor handle", "pass each source as {path}")
		}
		add(s.Path)
	}

	if in.Directory != "" {
		confinedDir, err := hdfutil.SafePath(mcpRoot(), in.Directory)
		if err != nil {
			return nil, mcperr.New(mcperr.PathDenied, "directory resolves outside HDF_MCP_ROOT", map[string]any{"path": in.Directory})
		}
		entries, rerr := os.ReadDir(confinedDir)
		if rerr != nil {
			return nil, mcperr.New(mcperr.DocumentNotFound, "cannot read the batch directory", map[string]any{"path": in.Directory}).
				WithNextCall("verify the directory exists under HDF_MCP_ROOT")
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if in.Pattern != "" {
				ok, mErr := filepath.Match(in.Pattern, e.Name())
				if mErr != nil {
					return nil, mcperr.Arg("invalid pattern: "+mErr.Error(), "pass a valid glob pattern (*, ?, [..])")
				}
				if !ok {
					continue
				}
			}
			add(path.Join(in.Directory, e.Name()))
		}
	}

	if len(rels) == 0 {
		return nil, mcperr.Arg("no input files matched", "pass sources[] with at least one path, or a directory containing files")
	}
	sort.Strings(rels)
	return rels, nil
}

// convertOneFile runs the full single-file pipeline for one batch member and
// returns its summary entry. Any detection/read/conversion/validation failure
// becomes an error entry (taxonomy code + message) rather than aborting the
// batch. A conversion that succeeds but whose write fails keeps valid:true and
// surfaces the write error, with the handle resolving from the in-memory cache.
func convertOneFile(ldr *loader.Loader, rel string, in convertInput, shouldWrite bool) fileConvertSummary {
	entry := fileConvertSummary{InputPath: rel}
	confined, err := hdfutil.SafePath(mcpRoot(), rel)
	if err != nil {
		return failEntry(entry, mcperr.New(mcperr.PathDenied, "path resolves outside HDF_MCP_ROOT", map[string]any{"path": rel}))
	}
	data, terr := readFile(confined, rel, "sources")
	if terr != nil {
		return failEntry(entry, terr)
	}
	conv, terr := resolveConverter(in.From, data)
	if terr != nil {
		return failEntry(entry, terr)
	}
	hdfBytes, terr := convertAndPostProcess(conv, data, in.Labels, in.ComponentID)
	if terr != nil {
		return failEntry(entry, terr)
	}
	if terr := refuseInvalidResults(hdfBytes); terr != nil {
		return failEntry(entry, terr)
	}

	sum := convertSummary(hdfBytes)
	entry.DocType = sum.DocType
	entry.BaselineCount = sum.BaselineCount
	entry.RequirementCount = sum.RequirementCount
	entry.Sha256 = sum.Sha256
	entry.Valid = true

	// Register in the content cache so the handle resolves even with no write.
	_, _ = ldr.Load(hdfBytes)

	writtenPath := ""
	if shouldWrite {
		wp, _, werr := writeArtifact(batchOutputPath(in.OutputDir, rel), false, in.Overwrite, hdfBytes)
		if werr != nil {
			entry.Error = werr.Message
			entry.Code = string(werr.Code)
		} else {
			writtenPath = wp
			entry.OutputPath = wp
		}
	}
	if encoded, herr := handle.Encode(handle.Compute(writtenPath, hdfBytes, "results", hdfengine.Version())); herr == nil {
		entry.Handle = encoded
	}
	return entry
}

// failEntry marks a batch member as failed, carrying the taxonomy code + message.
func failEntry(entry fileConvertSummary, terr *mcperr.Error) fileConvertSummary {
	entry.Valid = false
	entry.Error = terr.Message
	entry.Code = string(terr.Code)
	return entry
}

// batchOutputPath derives an output path deterministically from the input, using
// the CLI's <stem>.hdf.json bulk-convert convention (bead g4b3 owns any change).
// Paths are forward-slash on the wire (like agent-supplied paths and URLs) so
// the MCP surface is identical across host OSes; SafePath converts to the native
// separator at the filesystem boundary.
func batchOutputPath(outputDir, inputPath string) string {
	base := path.Base(inputPath)
	stem := strings.TrimSuffix(base, path.Ext(base))
	return path.Join(outputDir, stem+".hdf.json")
}

// boundBatchResponse token-bounds the per-file array to the concise budget,
// dropping trailing entries (never silently) and stating how many were dropped.
func boundBatchResponse(out *convertOutput) {
	if respond.EstimateTokens(mustJSON(out)) <= respond.ConciseTokenBudget {
		return
	}
	total := len(out.Batch)
	lo, hi, best := 0, total, 0
	for lo <= hi {
		mid := (lo + hi) / 2
		trial := *out
		trial.Batch = out.Batch[:mid]
		trial.Truncated = false
		trial.Notice = ""
		if respond.EstimateTokens(mustJSON(&trial)) <= respond.ConciseTokenBudget {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	out.Batch = out.Batch[:best]
	out.Truncated = true
	trunc := fmt.Sprintf(
		"Response truncated to stay within the %d-token budget: returned %d of %d file summaries (%d dropped). Convert the remaining files in a follow-up batch call (e.g. a narrower pattern or an explicit sources[] slice).",
		respond.ConciseTokenBudget, best, total, total-best)
	if out.Notice != "" {
		out.Notice = trunc + " " + out.Notice
	} else {
		out.Notice = trunc
	}
}

// convertAndPostProcess runs the converter and threads labels/componentId onto
// the output. Every failure becomes a taxonomy error so the caller never checks
// a bare error against a nil return.
func convertAndPostProcess(conv convreg.Converter, data []byte, labels map[string]string, componentID string) ([]byte, *mcperr.Error) {
	hdfBytes, err := conv.Convert(data)
	if err != nil {
		return nil, mcperr.New(mcperr.SchemaInvalid, "conversion failed: "+err.Error(), nil).
			WithNextCall("verify the input is valid output from the source tool")
	}
	if hdfBytes, err = hdfdoc.ApplyLabels(hdfBytes, labels); err != nil {
		return nil, mcperr.New(mcperr.SchemaInvalid, "applying labels failed: "+err.Error(), nil)
	}
	if hdfBytes, err = hdfdoc.ApplyComponentID(hdfBytes, componentID, false); err != nil {
		return nil, mcperr.New(mcperr.SchemaInvalid, "applying componentId failed: "+err.Error(), nil)
	}
	return hdfBytes, nil
}

// rawInput returns the raw tool-output bytes from a {path} source or inline
// content. hdf_convert takes raw tool output, not an HDF handle.
func rawInput(src *handle.Source, content string) ([]byte, *mcperr.Error) {
	hasContent := content != ""
	hasSource := src != nil && (src.Path != "" || src.Handle != "")
	switch {
	case hasContent && hasSource:
		return nil, mcperr.Arg("pass either source or content, not both", "pass exactly one of source or content")
	case hasContent:
		return []byte(content), nil
	case hasSource:
		if src.Handle != "" {
			return nil, mcperr.New(mcperr.DocumentNotFound, "hdf_convert takes raw tool output by path or inline content, not an HDF handle", nil).
				WithNextCall("pass source.path to the raw tool-output file, or inline content")
		}
		confined, err := hdfutil.SafePath(mcpRoot(), src.Path)
		if err != nil {
			return nil, mcperr.New(mcperr.PathDenied, "path resolves outside HDF_MCP_ROOT", map[string]any{"path": src.Path})
		}
		return readFile(confined, src.Path, "source")
	default:
		return nil, mcperr.New(mcperr.DocumentNotFound, "no source or content provided", nil).
			WithNextCall("pass source.path or inline content")
	}
}

// resolveConverter picks the source→HDF converter: the given from, or the
// fingerprint auto-detection. An unresolvable format is AMBIGUOUS_FORMAT (a
// confidence tie) or NO_CONVERTER (nothing matched / no registered converter).
func resolveConverter(from string, data []byte) (convreg.Converter, *mcperr.Error) {
	format := from
	if format == "" {
		all := registry.DetectConverterAll(data)
		if len(all) == 0 {
			return nil, mcperr.New(mcperr.NoConverter, "could not detect the source format", nil).
				WithNextCall("pass from explicitly (see the hdf://catalog/converters resource)")
		}
		best := registry.DetectConverter(data)
		if best == nil {
			if len(all) > 1 && all[1].Confidence == all[0].Confidence {
				return nil, mcperr.New(mcperr.AmbiguousFormat, "the source format is ambiguous between more than one converter", nil).
					WithNextCall("pass from explicitly to disambiguate")
			}
			return nil, mcperr.New(mcperr.NoConverter, "no confident source-format match", nil).
				WithNextCall("pass from explicitly (see the hdf://catalog/converters resource)")
		}
		format = best.Fingerprint.ID
		if idx := strings.Index(format, "-to-"); idx > 0 {
			format = format[:idx]
		}
	}
	conv, err := convreg.GetConverter(format, "hdf")
	if err != nil {
		return nil, mcperr.New(mcperr.NoConverter, fmt.Sprintf("no converter for source format %q", format), map[string]any{"from": format}).
			WithNextCall("check the hdf://catalog/converters resource for supported `from` formats")
	}
	return conv, nil
}

// refuseInvalidResults returns SCHEMA_INVALID when the converted document does
// not validate as hdf-results — the tool must never write or hand back a bad
// artifact.
func refuseInvalidResults(hdfBytes []byte) *mcperr.Error {
	vr := validators.ValidateResults(hdfBytes)
	if vr.Valid {
		return nil
	}
	return mcperr.New(mcperr.SchemaInvalid, "the converted document does not validate as hdf-results: "+vr.Error(), nil).
		WithNextCall("this indicates a converter defect; do not rely on the output")
}

// convertSummary builds the summary-only response (no document body) for a valid
// converted document.
func convertSummary(hdfBytes []byte) convertOutput {
	var results hdf.HDFResults
	_ = json.Unmarshal(hdfBytes, &results)
	reqCount := 0
	for i := range results.Baselines {
		reqCount += len(results.Baselines[i].Requirements)
	}
	sum := sha256.Sum256(hdfBytes)
	return convertOutput{
		DocType:          "results",
		BaselineCount:    len(results.Baselines),
		RequirementCount: reqCount,
		Sha256:           hex.EncodeToString(sum[:]),
		Valid:            true,
	}
}
