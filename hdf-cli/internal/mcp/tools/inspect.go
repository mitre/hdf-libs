package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	appmcp "github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/handle"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/loader"
	"github.com/mitre/hdf-libs/hdf-cli/v3/internal/mcp/respond"
	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type inspectInput struct {
	Source    handle.Source `json:"source" jsonschema:"document as {path} or {handle}"`
	Section   string        `json:"section,omitempty" jsonschema:"one structural section (validity depends on doc type)"`
	Verbosity string        `json:"verbosity,omitempty" jsonschema:"concise (default) or full"`
	Page      int           `json:"page,omitempty" jsonschema:"0-based page when truncated"`
}

type inspectOutput struct {
	Handle              string            `json:"handle"`
	DocType             string            `json:"docType"`
	EngineSchemaVersion string            `json:"engineSchemaVersion"`
	Valid               bool              `json:"valid"`
	ValidationErrors    []validationError `json:"validationErrors,omitempty"`
	Section             string            `json:"section,omitempty"`
	Structure           map[string]any    `json:"structure,omitempty"`
	Truncated           bool              `json:"truncated,omitempty"`
	NextPage            int               `json:"nextPage,omitempty"`
	Notice              string            `json:"notice,omitempty"`
}

// RegisterInspect registers hdf_inspect on the server.
func RegisterInspect(s *sdkmcp.Server, ldr *loader.Loader) {
	sdkmcp.AddTool(s, &sdkmcp.Tool{
		Name: "hdf_inspect",
		Description: "Inspect an HDF document's structure and metadata for any of the eight document types " +
			"(counts, inventories, envelopes) — never a requirement collection. To list requirements, use hdf_query.",
		Annotations: appmcp.ReadOnly(),
	}, hdfInspect(ldr))
}

func hdfInspect(ldr *loader.Loader) sdkmcp.ToolHandlerFor[inspectInput, inspectOutput] {
	return func(_ context.Context, _ *sdkmcp.CallToolRequest, in inspectInput) (*sdkmcp.CallToolResult, inspectOutput, error) {
		resolved, terr := resolveSource(in.Source, ldr, "source")
		if terr != nil {
			return toolError(terr), inspectOutput{}, nil
		}
		encoded, err := handle.Encode(resolved.Handle)
		if err != nil {
			return nil, inspectOutput{}, fmt.Errorf("encoding handle: %w", err)
		}

		out := inspectOutput{
			Handle:              encoded,
			DocType:             resolved.Load.DocType,
			EngineSchemaVersion: resolved.Handle.EngineSchemaVersion,
			Valid:               resolved.Load.Valid,
		}
		if !resolved.Load.Valid {
			out.ValidationErrors = toValidationErrors(resolved.Load.Errors)
			return nil, out, nil
		}

		structure := buildStructure(resolved.Load.Engine, resolved.Content)
		out.Structure, out.Section, out.Notice = selectSection(structure, in.Section, out.DocType)
		boundInspectResponse(&out, in.Verbosity, in.Page)
		return nil, out, nil
	}
}

// selectSection returns the requested section of the structure (or the whole
// structure when no section is given). A section not valid for this document
// type yields the full structure plus a notice naming the valid sections.
func selectSection(structure map[string]any, section, docType string) (map[string]any, string, string) {
	if section == "" {
		return structure, "", ""
	}
	if v, ok := structure[section]; ok {
		return map[string]any{section: v}, section, ""
	}
	valid := make([]string, 0, len(structure))
	for k := range structure {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	return structure, "", fmt.Sprintf(
		"section %q is not valid for a %s document; returning the full structure. valid sections: %s",
		section, docType, strings.Join(valid, ", "),
	)
}

// buildStructure produces the type-specific structural view. It never includes a
// requirement collection — results/baseline expose requirement COUNTS only.
func buildStructure(lr *hdfengine.LoadResult, content []byte) map[string]any {
	switch lr.DocType {
	case "results":
		return resultsStructure(lr.Results)
	case "baseline":
		return baselineStructure(lr.Baseline)
	case "system":
		return genericStructure(content, systemShape)
	case "plan":
		return genericStructure(content, planShape)
	case "amendments":
		return genericStructure(content, amendmentsShape)
	case "evidence-package":
		return genericStructure(content, evidenceShape)
	case "comparison":
		return genericStructure(content, comparisonShape)
	case "requirement-change-event":
		return genericStructure(content, changeEventShape)
	default:
		return map[string]any{"metadata": map[string]any{"docType": lr.DocType}}
	}
}

func resultsStructure(r *hdf.HDFResults) map[string]any {
	if r == nil {
		return map[string]any{}
	}
	baselines := make([]map[string]any, 0, len(r.Baselines))
	for i := range r.Baselines {
		b := &r.Baselines[i]
		counts := countByEffectiveStatus(hdf.HDFResults{Baselines: []hdf.EvaluatedBaseline{*b}})
		baselines = append(baselines, map[string]any{
			"name":             b.Name,
			"requirementCount": len(b.Requirements),
			"statusBreakdown": map[string]int{
				"passed": counts.Passed.Total, "failed": counts.Failed.Total,
				"notApplicable": counts.NoImpact.Total, "notReviewed": counts.Skipped.Total, "error": counts.Error.Total,
			},
		})
	}
	byType := map[string]int{}
	for i := range r.Components {
		byType[string(r.Components[i].Type)]++
	}
	return map[string]any{
		"baselines":  baselines,
		"components": map[string]any{"count": len(r.Components), "byType": byType},
		"statistics": map[string]any{"duration": r.Statistics.Duration},
		"metadata":   docMetadata(r.ID, r.SystemRef, r.PlanRef),
	}
}

func baselineStructure(b *hdf.HDFBaseline) map[string]any {
	if b == nil {
		return map[string]any{}
	}
	groups := make([]string, 0, len(b.Groups))
	for i := range b.Groups {
		if b.Groups[i].ID != "" {
			groups = append(groups, b.Groups[i].ID)
		}
	}
	return map[string]any{
		"structure": map[string]any{"requirementCount": len(b.Requirements), "groupCount": len(b.Groups)},
		"groups":    groups,
		"metadata":  map[string]any{"name": b.Name, "title": strPtrOrEmpty(b.Title)},
	}
}

// genericStructure unmarshals the raw content and applies a shape function that
// extracts the type-specific structure from the decoded map (for the document
// types the engine core does not struct-parse).
func genericStructure(content []byte, shape func(map[string]any) map[string]any) map[string]any {
	var doc map[string]any
	if err := json.Unmarshal(content, &doc); err != nil {
		return map[string]any{}
	}
	return shape(doc)
}

func systemShape(doc map[string]any) map[string]any {
	comps := asArray(doc["components"])
	byType := map[string]int{}
	for _, c := range comps {
		if m, ok := c.(map[string]any); ok {
			byType[asString(m["type"])]++
		}
	}
	return map[string]any{
		"components": map[string]any{"count": len(comps), "byType": byType},
		"dataflows":  map[string]any{"count": len(asArray(doc["dataFlows"]))},
		"controls":   map[string]any{"count": len(asArray(doc["controlDesignations"]))},
		"metadata":   map[string]any{"name": asString(doc["name"]), "systemID": asString(doc["systemId"]), "authorizationStatus": asString(doc["authorizationStatus"])},
	}
}

func planShape(doc map[string]any) map[string]any {
	assessments := asArray(doc["assessments"])
	return map[string]any{
		"assessments": map[string]any{"count": len(assessments)},
		"schedule":    doc["schedule"],
		"metadata":    map[string]any{"name": asString(doc["name"]), "planID": asString(doc["planId"]), "systemRef": asString(doc["systemRef"])},
	}
}

func amendmentsShape(doc map[string]any) map[string]any {
	overrides := asArray(doc["overrides"])
	byType := map[string]int{}
	for _, o := range overrides {
		if m, ok := o.(map[string]any); ok {
			byType[asString(m["type"])]++
		}
	}
	return map[string]any{
		"overrides": map[string]any{"count": len(overrides), "byType": byType},
		"metadata":  map[string]any{"name": asString(doc["name"]), "amendmentID": asString(doc["amendmentId"]), "systemRef": asString(doc["systemRef"])},
	}
}

func evidenceShape(doc map[string]any) map[string]any {
	contents := asArray(doc["contents"])
	items := make([]map[string]any, 0, len(contents))
	for _, c := range contents {
		if m, ok := c.(map[string]any); ok {
			items = append(items, map[string]any{"type": asString(m["type"]), "uri": asString(m["uri"])})
		}
	}
	return map[string]any{
		"contents":     items,
		"completeness": doc["completenessCheck"],
		"metadata":     map[string]any{"name": asString(doc["name"]), "packageID": asString(doc["packageId"])},
	}
}

func comparisonShape(doc map[string]any) map[string]any {
	return map[string]any{
		"summary": doc["summary"],
		"diffs": map[string]any{
			"baselineDiffs":    len(asArray(doc["baselineDiffs"])),
			"componentDiffs":   len(asArray(doc["componentDiffs"])),
			"requirementDiffs": len(asArray(doc["requirementDiffs"])),
			"drift":            len(asArray(doc["drift"])),
			"packageDiffs":     len(asArray(doc["packageDiffs"])),
		},
		"metadata": map[string]any{"comparisonMode": asString(doc["comparisonMode"]), "systemRef": asString(doc["systemRef"])},
	}
}

func changeEventShape(doc map[string]any) map[string]any {
	return map[string]any{
		"envelope": map[string]any{
			"eventId": asString(doc["eventId"]), "source": asString(doc["source"]),
			"sequence": doc["sequence"], "schemaRef": asString(doc["schemaRef"]),
			"priorChecksum": doc["priorChecksum"], "timestamp": asString(doc["timestamp"]),
			"systemRef": asString(doc["systemRef"]),
		},
		"change": map[string]any{
			"requirementId": asString(doc["requirementId"]), "state": asString(doc["state"]),
			"componentId": asString(doc["componentId"]), "changeReasons": doc["changeReasons"],
		},
	}
}

// boundInspectResponse enforces the verbosity token budget on the serialized
// structure. When over budget it drops structure keys deterministically and
// notes the remedy, so a large structure never blows the budget silently.
func boundInspectResponse(out *inspectOutput, verbosity string, page int) {
	budget := respond.ConciseTokenBudget
	if verbosity == "full" {
		budget = respond.FullTokenBudget
	}
	if page == 0 && respond.EstimateTokens(mustJSON(out)) <= budget {
		return
	}

	// Partition the sorted structure keys into budget-sized pages so paging
	// actually retrieves the dropped sections, then return the requested page.
	pages := paginateStructure(out, budget)
	if page < 0 || page >= len(pages) {
		out.Structure = map[string]any{}
		out.Truncated = true
		out.Notice = fmt.Sprintf("page %d is out of range (%d page(s)); page 0 is the first.", page, len(pages))
		return
	}
	sel := map[string]any{}
	for _, k := range pages[page] {
		sel[k] = out.Structure[k]
	}
	out.Structure = sel
	if len(pages) > 1 {
		out.Truncated = true
		if page+1 < len(pages) {
			out.NextPage = page + 1
		}
		out.Notice = fmt.Sprintf(
			"Structure spans %d pages within the %s token budget (%d); showing page %d. Request a specific section, or page through with page=N.",
			len(pages), verbosityLabel(verbosity), budget, page,
		)
	}
}

// paginateStructure greedily packs the sorted structure keys into pages that
// each fit the token budget (including the fixed envelope). A single key too
// large to fit alone gets its own page so paging always makes progress.
func paginateStructure(out *inspectOutput, budget int) [][]string {
	keys := make([]string, 0, len(out.Structure))
	for k := range out.Structure {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var pages [][]string
	i := 0
	for i < len(keys) {
		var cur []string
		for i < len(keys) {
			trial := *out
			sel := map[string]any{}
			for _, k := range cur {
				sel[k] = out.Structure[k]
			}
			sel[keys[i]] = out.Structure[keys[i]]
			trial.Structure = sel
			trial.Notice = ""
			trial.Truncated = true
			trial.NextPage = 1
			if respond.EstimateTokens(mustJSON(&trial)) > budget && len(cur) > 0 {
				break // this key belongs on the next page
			}
			cur = append(cur, keys[i])
			i++
		}
		pages = append(pages, cur)
	}
	if len(pages) == 0 {
		pages = append(pages, nil)
	}
	return pages
}

func verbosityLabel(v string) string {
	if v == "full" {
		return "full"
	}
	return "concise"
}

// --- small helpers ---

func docMetadata(id, systemRef, planRef *string) map[string]any {
	return map[string]any{"id": strPtrOrEmpty(id), "systemRef": strPtrOrEmpty(systemRef), "planRef": strPtrOrEmpty(planRef)}
}

func asArray(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strPtrOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
