// Package bom provides a shared parser that detects and normalizes CycloneDX,
// SPDX, and CycloneDX ML BOM documents into the HDF BillOfMaterials shape
// (ADR-0001 Phase 2 / kirq.2). It is the Go peer of
// hdf-converters/shared/typescript/bom and must stay behaviorally equivalent on
// the same fixtures.
//
// The package re-exports the generated HDF Bill-of-Materials types so the parser
// and its consumers depend on a single source of truth, and defines the
// relational graph scaffolding reserved for future CBOM/SaaSBOM normalization.
// The graph types are present but UNPOPULATED today — they satisfy the card's
// "supports relational extensions" contract without asserting relationships no
// current format cleanly provides.
//
// ASYMMETRY NOTE (parity with TypeScript): the TS peer registers its three BOM
// fingerprints in a shared ConverterFingerprint registry; Go has no such
// registry. Parity is at the LOGIC level — DetectFormat exists in both — while
// CLI auto-detect wiring is Phase 3 in both languages.
package bom

import hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"

// Generated HDF Bill-of-Materials types re-exported as the package's public
// vocabulary, so consumers import a single source of truth.
type (
	BillOfMaterials     = hdf.BillOfMaterials
	SBOMPackage         = hdf.SBOMPackage
	AIModelBOMExtension = hdf.AIModelBOMExtension
	DatasetBOMExtension = hdf.DatasetBOMExtension
	InputOutput         = hdf.InputOutput
	PerformanceMetric   = hdf.PerformanceMetric
	Hyperparameter      = hdf.Hyperparameter
	Modality            = hdf.Modality
	Checksum            = hdf.Checksum
)

// BOMType is the manifest-kind discriminator. The schema allows custom
// 'x-'-prefixed kinds beyond the reserved set, so the generated field is a
// plain string; the reserved values below are the package's normalized
// vocabulary.
type BOMType = string

// Reserved BOM manifest kinds this parser normalizes.
const (
	BOMTypeSbom    BOMType = "sbom"
	BOMTypeAIModel BOMType = "ai-model"
	BOMTypeDataset BOMType = "dataset"
)

// Supported source BOM formats the parser can detect and normalize.
const (
	FormatCycloneDX     = "cyclonedx"
	FormatSPDX          = "spdx"
	FormatCycloneDXML   = "cyclonedx-ml"
	FormatSPDX3AI       = "spdx-3-ai"
	FormatSPDX3Security = "spdx-3-security"
)

// RelationalNode is a node in the reserved relational-BOM graph (CBOM
// cryptographic assets, SaaSBOM services, dependency edges). Reserved
// scaffolding — not populated by the current CycloneDX/SPDX/ML parsers.
type RelationalNode struct {
	// ID is a stable identifier within the graph (e.g. a bom-ref or SPDXID).
	ID string `json:"id"`
	// Kind is the node category (e.g. "component", "service", "crypto-algorithm").
	Kind string `json:"kind"`
	// Label is a human-readable label.
	Label string `json:"label,omitempty"`
	// Attributes are opaque per-node attributes carried until a normalized shape ships.
	Attributes map[string]any `json:"attributes,omitempty"`
}

// RelationalEdge is a directed relationship in the reserved relational-BOM graph
// (e.g. DEPENDS_ON, DESCRIBES). Reserved scaffolding — not populated today.
type RelationalEdge struct {
	// From is the source node id.
	From string `json:"from"`
	// To is the target node id.
	To string `json:"to"`
	// Relationship is the relationship type (e.g. "depends-on", "describes").
	Relationship string `json:"relationship"`
	// Attributes are opaque per-edge attributes.
	Attributes map[string]any `json:"attributes,omitempty"`
}

// NormalizedBom is the normalized parser output: a schema-valid BillOfMaterials
// plus optional relational-graph scaffolding. BuildBom emits the
// BillOfMaterials core; Nodes/Edges stay nil until a relational format is
// normalized. Mirrors the TS NormalizedBom = BillOfMaterials & { nodes?, edges? }.
type NormalizedBom struct {
	BillOfMaterials
	Nodes []RelationalNode `json:"nodes,omitempty"`
	Edges []RelationalEdge `json:"edges,omitempty"`
}
