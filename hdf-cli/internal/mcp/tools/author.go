package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"
	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// authorInput is the hdf_author argument surface. The content array is opaque
// structured JSON — its exact per-docType shape lives in the hdf://schema
// resources, not this tool schema (embedding the full polymorphic HDF types
// would bloat the surface and produce client-rejected bare-boolean schemas). The
// server validates the assembled document against the real schema and refuses
// invalid content, so the shape contract is authoritative at runtime.
type authorInput struct {
	DocType string           `json:"docType" jsonschema:"the document to author: system, plan, or evidence"`
	Name    string           `json:"name" jsonschema:"the document name"`
	Content []map[string]any `json:"content" jsonschema:"the content array — components (system), assessments (plan), or contents (evidence). Learn the exact shape from the hdf://schema/hdf-<docType> resource; the server validates and refuses invalid content."`
	Output  string           `json:"output,omitempty" jsonschema:"path under HDF_MCP_ROOT to write the document"`
	DryRun  bool             `json:"dryRun,omitempty" jsonschema:"with output set, preview the write (write no file)"`
}

// authorOutput is summary-only — never the assembled document body.
type authorOutput struct {
	OutputPath     string `json:"outputPath,omitempty"`
	Handle         string `json:"handle"`
	DocType        string `json:"docType"`
	Name           string `json:"name"`
	ItemCount      int    `json:"itemCount"`
	Sha256         string `json:"sha256"`
	Valid          bool   `json:"valid"`
	WritesDisabled bool   `json:"writesDisabled,omitempty"`
	Notice         string `json:"notice,omitempty"`
}

// RegisterAuthor registers the hdf_author tool on the server.
func RegisterAuthor(s *sdkmcp.Server) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_author",
		Description: "Author an HDF document from model-supplied structured content: the model supplies the content array; the server assembles the schema-valid envelope (name, generator), validates it, and returns a summary plus a reusable handle — never the document body. docType is system (components), plan (assessments), or evidence (contents); the exact per-type shape lives in the hdf://schema/hdf-<docType> resources. Output that does not validate is refused. Writes under the shared write model (dry_run previews; a writes-disabled deployment returns a preview).",
		Annotations: appmcp.Writing(false, true),
	}, hdfAuthor())
}

func hdfAuthor() sdkmcp.ToolHandlerFor[authorInput, authorOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in authorInput) (*sdkmcp.CallToolResult, authorOutput, error) {
		switch in.DocType {
		case "system", "plan", "evidence":
		default:
			return argError(fmt.Sprintf("unknown docType %q", in.DocType), "use docType system, plan, or evidence"), authorOutput{}, nil
		}

		gen := &hdf.Generator{Name: "hdf-mcp", Version: hdfengine.Version()}
		docBytes, st, terr := assembleAuthored(in.DocType, in.Name, in.Content, gen)
		if terr != nil {
			return toolError(terr), authorOutput{}, nil
		}

		out := authorOutput{DocType: in.DocType, Name: in.Name, ItemCount: len(in.Content)}

		vr := validators.Validate(docBytes, st)
		out.Valid = vr.Valid
		if !vr.Valid {
			return toolError(mcperr.New(mcperr.SchemaInvalid,
				fmt.Sprintf("the authored %s document does not validate: %s", in.DocType, vr.Error()), nil).
				WithNextCall("fix the content; consult the hdf://schema/hdf-" + resourceSlug(in.DocType) + " resource for the required shape")), authorOutput{}, nil
		}
		sum := sha256.Sum256(docBytes)
		out.Sha256 = hex.EncodeToString(sum[:])

		writtenPath, notice, werr := writeArtifact(in.Output, in.DryRun, docBytes)
		if werr != nil {
			return toolError(werr), authorOutput{}, nil
		}
		out.OutputPath = writtenPath
		if notice != "" {
			out.Notice = notice
			out.WritesDisabled = strings.Contains(notice, "WRITES_DISABLED")
		}

		encoded, herr := handle.Encode(handle.Compute(in.Output, docBytes, string(st), hdfengine.Version()))
		if herr != nil {
			return nil, authorOutput{}, fmt.Errorf("encoding handle: %w", herr)
		}
		out.Handle = encoded
		return nil, out, nil
	}
}

// assembleAuthored builds the document losslessly via the shared builders (the
// content is copied verbatim, no field re-typed or dropped).
func assembleAuthored(docType, name string, content []map[string]any, gen *hdf.Generator) ([]byte, validators.SchemaType, *mcperr.Error) {
	var (
		b   []byte
		err error
		st  validators.SchemaType
	)
	switch docType {
	case "system":
		b, err = hdfdoc.BuildSystem(name, content, gen)
		st = validators.TypeSystem
	case "plan":
		b, err = hdfdoc.BuildPlan(name, content, gen)
		st = validators.TypePlan
	default: // evidence (docType already validated by the caller)
		b, err = hdfdoc.BuildEvidencePackage(name, content, gen)
		st = validators.TypeEvidencePackage
	}
	if err != nil {
		return nil, "", mcperr.New(mcperr.SchemaInvalid, "could not assemble the document: "+err.Error(), nil)
	}
	return b, st, nil
}

// resourceSlug maps a docType to its hdf://schema resource slug.
func resourceSlug(docType string) string {
	if docType == "evidence" {
		return "evidence-package"
	}
	return docType
}
