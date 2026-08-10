package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"
	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
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
	Content     string            `json:"content,omitempty" jsonschema:"inline raw tool output (alternative to source)"`
	From        string            `json:"from,omitempty" jsonschema:"source format (e.g. nessus, gosec); auto-detected when omitted"`
	Output      string            `json:"output,omitempty" jsonschema:"path under HDF_MCP_ROOT to write the HDF results document"`
	DryRun      bool              `json:"dryRun,omitempty" jsonschema:"with output set, preview the write (return the summary, write no file)"`
	Labels      map[string]string `json:"labels,omitempty" jsonschema:"labels to apply to every component in the output"`
	ComponentID string            `json:"componentId,omitempty" jsonschema:"componentId to set on every component in the output"`
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
}

// RegisterConvert registers the hdf_convert tool on the server.
func RegisterConvert(s *sdkmcp.Server) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_convert",
		Description: "Convert source security-tool output into an HDF results document and return a compact SUMMARY (counts, hash, validity) plus a reusable handle — never the converted body, which is routinely megabytes. Conversion goes through the shared converter registry; from is auto-detected (including NDJSON) when omitted. With output set it writes under the shared write model (dry_run previews; a writes-disabled deployment returns a preview). Output that does not validate as hdf-results is refused.",
		Annotations: appmcp.Writing(false, true),
	}, hdfConvert())
}

func hdfConvert() sdkmcp.ToolHandlerFor[convertInput, convertOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in convertInput) (*sdkmcp.CallToolResult, convertOutput, error) {
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

		writtenPath, notice, werr := writeArtifact(in.Output, in.DryRun, hdfBytes)
		if werr != nil {
			return toolError(werr), convertOutput{}, nil
		}
		out.OutputPath = writtenPath
		if notice != "" {
			out.Notice = notice
			out.WritesDisabled = strings.Contains(notice, "WRITES_DISABLED")
		}

		encoded, herr := handle.Encode(handle.Compute(in.Output, hdfBytes, "results", hdfengine.Version()))
		if herr != nil {
			return nil, convertOutput{}, fmt.Errorf("encoding handle: %w", herr)
		}
		out.Handle = encoded
		return nil, out, nil
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
		return nil, mcperr.New(mcperr.AmbiguousFormat, "pass either source or content, not both", nil).
			WithNextCall("pass exactly one of source or content")
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
		return readFile(confined)
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
