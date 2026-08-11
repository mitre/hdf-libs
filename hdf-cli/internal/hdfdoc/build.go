package hdfdoc

import (
	"encoding/json"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// The canonical minimal-document builders for the three inventory document types
// (system, plan, evidence-package). They are the shared assembly point the CLI
// and the MCP use instead of hand-building document literals, mirroring the
// hdf-schema createMinimal* helpers (which cover only results/baseline). They
// live here rather than in hdf-schema because that package's Go module is
// generated output (dist/go); these are hand-written application-layer helpers
// shared by the two Go artifacts in this module.
//
// The content array is carried as []map[string]any and copied into the document
// verbatim — no field is dropped or re-typed — so a caller's structured content
// survives the build losslessly (proven by the round-trip tests). Each builder
// sets only the schema-required top-level fields (name + the content array) plus
// an optional generator; validation against the document schema is the caller's
// step (the content array is minItems:1, so an empty one is rejected there).

// BuildSystem assembles a minimal hdf-system document from a name and components.
func BuildSystem(name string, components []map[string]any, generator *hdf.Generator) ([]byte, error) {
	return buildDoc(name, "components", components, generator)
}

// BuildPlan assembles a minimal hdf-plan document from a name and assessments.
func BuildPlan(name string, assessments []map[string]any, generator *hdf.Generator) ([]byte, error) {
	return buildDoc(name, "assessments", assessments, generator)
}

// BuildEvidencePackage assembles a minimal hdf-evidence-package document from a
// name and contents.
func BuildEvidencePackage(name string, contents []map[string]any, generator *hdf.Generator) ([]byte, error) {
	return buildDoc(name, "contents", contents, generator)
}

// BuildAmendments assembles a minimal hdf-amendments document from a name and
// overrides. Like the other builders it copies the overrides verbatim; the
// server's field-authority stamping (appliedBy/appliedAt) is the caller's step,
// applied to the override maps before this call.
func BuildAmendments(name string, overrides []map[string]any, generator *hdf.Generator) ([]byte, error) {
	return buildDoc(name, "overrides", overrides, generator)
}

// buildDoc assembles the envelope: name + the content array under contentKey +
// an optional generator. The content items are marshalled verbatim, preserving
// every field the caller supplied.
func buildDoc(name, contentKey string, content []map[string]any, generator *hdf.Generator) ([]byte, error) {
	doc := map[string]any{
		"name":     name,
		contentKey: content,
	}
	if generator != nil {
		doc["generator"] = generator
	}
	return json.MarshalIndent(doc, "", "  ")
}
