package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/hdfdoc"
	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/mcperr"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// authorInput is the hdf_author argument surface. The content array is opaque
// structured JSON — its exact per-docType shape lives in the hdf://schema
// resources, not this tool schema (embedding the full polymorphic HDF types
// would bloat the surface and produce client-rejected bare-boolean schemas). The
// server validates the assembled document against the real schema and refuses
// invalid content, so the shape contract is authoritative at runtime.
//
// For docType=amendments there are two authoring paths: the judgment path
// (content[] of overrides — the server stamps appliedBy.type=agent + appliedAt
// and requires a caller expiresAt on every override) and the from_vex path
// (source = a VEX document — the server derives overrides deterministically,
// stamping appliedBy.type=system and the top-level expiresAt on each).
type authorInput struct {
	DocType   string           `json:"docType" jsonschema:"document to author: system, plan, evidence, or amendments"`
	Name      string           `json:"name" jsonschema:"the document name"`
	Content   []map[string]any `json:"content,omitempty" jsonschema:"content array: components/assessments/contents, or overrides (amendments judgment path). Per-item shape: the hdf://schema/{docType}/{def} slice (e.g. hdf://schema/hdf-amendments/Standalone_Override), not the whole schema. The server validates and refuses invalid content."`
	Source    *handle.Source   `json:"source,omitempty" jsonschema:"amendments from_vex only: a VEX document as {path}; overrides are derived and stamped appliedBy.type=system"`
	ExpiresAt string           `json:"expiresAt,omitempty" jsonschema:"amendments from_vex only: RFC3339 expiry applied to every derived override"`
	Output    string           `json:"output,omitempty" jsonschema:"path under HDF_MCP_ROOT to write the document"`
	DryRun    bool             `json:"dryRun,omitempty" jsonschema:"with output set, preview the write (write no file)"`
	Overwrite bool             `json:"overwrite,omitempty" jsonschema:"replace an existing output file (default false)"`
}

// authorOutput is summary-only — never the assembled document body. ItemCount is
// the count of authored items: components/assessments/contents, or overrides for
// amendments (including those derived on the from_vex path).
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
func RegisterAuthor(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name:        "hdf_author",
		Description: "Author an HDF document from model-supplied structured content and return a summary plus a reusable handle — never the document body. docType is system (components), plan (assessments), evidence (contents), or amendments (overrides). For amendments the server holds field authority: the judgment path (content[] of overrides) stamps appliedBy.type=agent + appliedAt and requires expiresAt on each; the from_vex path (source = a VEX document + expiresAt) derives overrides and stamps appliedBy.type=system. Per-item shapes: the compact hdf://schema/{docType}/{def} slices, not the whole schema. Output that does not validate is refused. Writes under the shared write model (dry_run previews; a writes-disabled deployment returns a preview).",
		Annotations: appmcp.Writing(false, true),
	}, hdfAuthor(ldr))
}

func hdfAuthor(ldr *loader.Loader) sdkmcp.ToolHandlerFor[authorInput, authorOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in authorInput) (*sdkmcp.CallToolResult, authorOutput, error) {
		switch in.DocType {
		case "system", "plan", "evidence", "amendments":
		default:
			return argError(fmt.Sprintf("unknown docType %q", in.DocType), "use docType system, plan, evidence, or amendments"), authorOutput{}, nil
		}

		gen := &hdf.Generator{Name: "hdf-mcp", Version: hdfengine.Version()}
		docBytes, st, itemCount, res, terr := assembleDoc(in, gen)
		if res != nil {
			return res, authorOutput{}, nil
		}
		if terr != nil {
			return toolError(terr), authorOutput{}, nil
		}

		out := authorOutput{DocType: in.DocType, Name: in.Name, ItemCount: itemCount}

		vr := validators.Validate(docBytes, st)
		out.Valid = vr.Valid
		if !vr.Valid {
			return toolError(mcperr.New(mcperr.SchemaInvalid,
				fmt.Sprintf("the authored %s document does not validate: %s", in.DocType, vr.Error()), nil).
				WithNextCall("fix the content; consult the hdf://schema/hdf-" + resourceSlug(in.DocType) + "/{def} slice resources for the required per-item shape")), authorOutput{}, nil
		}
		sum := sha256.Sum256(docBytes)
		out.Sha256 = hex.EncodeToString(sum[:])

		writtenPath, notice, werr := writeArtifact(in.Output, in.DryRun, in.Overwrite, docBytes)
		if werr != nil {
			return toolError(werr), authorOutput{}, nil
		}
		out.OutputPath = writtenPath
		if notice != "" {
			out.Notice = notice
			out.WritesDisabled = strings.Contains(notice, "WRITES_DISABLED")
		}

		// Register the produced document in the content cache and mint the handle
		// against the ACTUAL written path — empty when nothing was written, which
		// routes resolution to the in-memory cache so author→apply→compliance
		// composes with writes disabled (jobi.1 / D1).
		_, _ = ldr.Load(docBytes)
		encoded, herr := handle.Encode(handle.Compute(writtenPath, docBytes, string(st), hdfengine.Version()))
		if herr != nil {
			return nil, authorOutput{}, fmt.Errorf("encoding handle: %w", herr)
		}
		out.Handle = encoded
		return nil, out, nil
	}
}

// assembleDoc dispatches on docType, returning the assembled bytes, the schema
// type, the authored-item count, an optional request-shape error result (caller
// mistake), and an optional taxonomy error. system/plan/evidence copy content
// verbatim; amendments carry the field-authority stamping.
func assembleDoc(in authorInput, gen *hdf.Generator) ([]byte, validators.SchemaType, int, *sdkmcp.CallToolResult, *mcperr.Error) {
	if in.DocType == "amendments" {
		b, count, res, terr := assembleAmendments(in, gen)
		return b, validators.TypeAmendments, count, res, terr
	}
	b, st, terr := assembleAuthored(in.DocType, in.Name, in.Content, gen)
	return b, st, len(in.Content), nil, terr
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

// assembleAmendments dispatches the two amendments authoring paths. Both are
// additive (a standalone hdf-amendments document; the results document the
// overrides target is never touched).
func assembleAmendments(in authorInput, gen *hdf.Generator) ([]byte, int, *sdkmcp.CallToolResult, *mcperr.Error) {
	hasSource := in.Source != nil && (in.Source.Path != "" || in.Source.Handle != "")
	hasContent := len(in.Content) > 0
	switch {
	case hasSource && hasContent:
		return nil, 0, argError("pass either content (judgment overrides) or source (from_vex), not both",
			"author amendments from model content, or derive them from a VEX source — not both in one call"), nil
	case hasSource:
		if strings.TrimSpace(in.ExpiresAt) == "" {
			return nil, 0, argError("from_vex requires expiresAt (RFC3339)",
				"set expiresAt; the deterministic mapping never fabricates a default expiry"), nil
		}
		b, count, terr := assembleFromVex(in, gen)
		return b, count, nil, terr
	case hasContent:
		b, count, terr := assembleJudgmentAmendments(in, gen)
		return b, count, nil, terr
	default:
		return nil, 0, argError("amendments needs content (judgment overrides) or source (from_vex)",
			"supply content[] of overrides for the judgment path, or a VEX source for from_vex"), nil
	}
}

// assembleJudgmentAmendments stamps the server's field-authority values on each
// model-supplied override (appliedBy.type=agent + appliedAt, requiring a caller
// expiresAt) and assembles the document. The model's own fields are preserved.
func assembleJudgmentAmendments(in authorInput, gen *hdf.Generator) ([]byte, int, *mcperr.Error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if terr := stampAgentOverrides(in.Content, now); terr != nil {
		return nil, 0, terr
	}
	b, err := hdfdoc.BuildAmendments(in.Name, in.Content, gen)
	if err != nil {
		return nil, 0, mcperr.New(mcperr.SchemaInvalid, "could not assemble the amendments document: "+err.Error(), nil)
	}
	return b, len(in.Content), nil
}

// assembleFromVex derives overrides from a VEX source via the shared
// deterministic mapping (appliedBy.type=system, caller expiresAt on each).
func assembleFromVex(in authorInput, gen *hdf.Generator) ([]byte, int, *mcperr.Error) {
	data, terr := vexBytes(in.Source)
	if terr != nil {
		return nil, 0, terr
	}
	expiresAt := hdfutil.ParseTimestamp(in.ExpiresAt)
	if expiresAt.IsZero() {
		return nil, 0, mcperr.New(mcperr.SchemaInvalid, "invalid expiresAt: not a recognized timestamp", nil).
			WithNextCall("pass expiresAt as RFC3339, e.g. 2027-01-01T00:00:00Z")
	}
	doc, err := hdfdoc.AmendmentsFromVex(data, expiresAt, hdfengine.Version())
	if err != nil {
		return nil, 0, mcperr.New(mcperr.SchemaInvalid, err.Error(), nil).
			WithNextCall("supply an OpenVEX document with at least one actionable (not_affected/fixed) statement")
	}
	doc.Generator = gen
	if in.Name != "" {
		doc.Name = in.Name
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, 0, mcperr.New(mcperr.SchemaInvalid, "could not serialize amendments: "+err.Error(), nil)
	}
	return b, len(doc.Overrides), nil
}

// stampAgentOverrides applies the judgment-path field authority to every
// override map in place: it requires a caller expiresAt (never defaulted),
// stamps appliedAt = now, and fixes appliedBy.type = agent (preserving a
// model-supplied identifier, else defaulting one) so the agent-override count
// stays honest — a model cannot claim a non-agent identity.
func stampAgentOverrides(overrides []map[string]any, now string) *mcperr.Error {
	for i, ov := range overrides {
		if exp, _ := ov["expiresAt"].(string); strings.TrimSpace(exp) == "" {
			return mcperr.New(mcperr.SchemaInvalid,
				fmt.Sprintf("override %d is missing the required expiresAt", i), nil).
				WithNextCall("set expiresAt (RFC3339) on every override; the server never invents an expiry")
		}
		ov["appliedAt"] = now
		ab, _ := ov["appliedBy"].(map[string]any)
		if ab == nil {
			ab = map[string]any{}
		}
		if id, _ := ab["identifier"].(string); strings.TrimSpace(id) == "" {
			ab["identifier"] = "hdf-mcp"
		}
		ab["type"] = string(hdf.Agent)
		ov["appliedBy"] = ab
	}
	return nil
}

// vexBytes reads a from_vex source: a raw VEX document by path under
// HDF_MCP_ROOT (not an HDF handle).
func vexBytes(src *handle.Source) ([]byte, *mcperr.Error) {
	if src.Handle != "" {
		return nil, mcperr.New(mcperr.DocumentNotFound,
			"the from_vex source is a raw VEX document by path, not an HDF handle", nil).
			WithNextCall("pass source.path to the VEX file under HDF_MCP_ROOT")
	}
	confined, err := hdfutil.SafePath(mcpRoot(), src.Path)
	if err != nil {
		return nil, mcperr.New(mcperr.PathDenied, "path resolves outside HDF_MCP_ROOT", map[string]any{"path": src.Path})
	}
	return readFile(confined, src.Path, "source")
}

// resourceSlug maps a docType to its hdf://schema resource slug.
func resourceSlug(docType string) string {
	if docType == "evidence" {
		return "evidence-package"
	}
	return docType
}
