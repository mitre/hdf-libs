// Package fixtures provides shared real-world HDF reference data for
// cross-package consumers. Each fixture is //go:embed-ed so test code in any
// monorepo package can read it without computing on-disk paths. The matching
// TS API lives at ./src/index.ts; both APIs point at the same physical files.
//
// Layout: top-level directories are by HDF document type (results/, baseline/,
// amendments/) plus inspec/ for InSpec runner output (non-HDF; kept for cross-
// language parser parity tests verifying both languages reject non-HDF
// inputs the same way).
//
// Boundary rule (per bead hdf-libs-e95o): converter fixtures stay with the
// converter as its tested contract; files here are wild-data references for
// cross-cutting tests. Inclusion requires the fixture is actually consumed
// by more than one workspace package — not just "might be useful someday."
//
// Provenance for every fixture is documented in ./README.md.
package fixtures

import _ "embed"

// ── HDF Results ──────────────────────────────────────────────────────────

//go:embed results/inspec-multilayered.json
var resultsInspecMultilayered []byte

//go:embed results/minimal.json
var resultsMinimal []byte

// Results exposes embedded HDF Results documents.
var Results = struct {
	InspecMultilayered []byte
	Minimal            []byte
}{
	InspecMultilayered: resultsInspecMultilayered,
	Minimal:            resultsMinimal,
}

// ── HDF Baseline ─────────────────────────────────────────────────────────

//go:embed baseline/win2022-stig.json
var baselineWin2022Stig []byte

// Baseline exposes embedded HDF Baseline documents.
var Baseline = struct {
	Win2022Stig []byte
}{
	Win2022Stig: baselineWin2022Stig,
}

// ── HDF Amendments ───────────────────────────────────────────────────────

//go:embed amendments/uc-01-fixed-amendments.json
var amendmentsUC01Fixed []byte

//go:embed amendments/multi-cve-amendments.json
var amendmentsMultiCVE []byte

// Amendments exposes embedded HDF Amendments documents.
var Amendments = struct {
	UC01Fixed []byte
	MultiCVE  []byte
}{
	UC01Fixed: amendmentsUC01Fixed,
	MultiCVE:  amendmentsMultiCVE,
}

// ── InSpec runner output (non-HDF) ───────────────────────────────────────

//go:embed inspec/ubi9-scan.json
var inspecUbi9Scan []byte

//go:embed inspec/container-scan.json
var inspecContainerScan []byte

//go:embed inspec/three-layer-overlay.json
var inspecThreeLayerOverlay []byte

//go:embed inspec/three-layer-rhel7.json
var inspecThreeLayerRhel7 []byte

//go:embed inspec/wrapper.json
var inspecWrapper []byte

// Inspec exposes embedded InSpec runner output. These are NOT HDF —
// they're the input format that legacyhdf-to-hdf converts. Kept here for
// cross-language parser parity tests that verify both languages reject
// non-HDF inputs the same way, and for the legacyhdf-to-hdf converter
// (which loads them via the materialize-to-tmp-file helper in its tests).
var Inspec = struct {
	Ubi9Scan          []byte
	ContainerScan     []byte
	ThreeLayerOverlay []byte
	ThreeLayerRhel7   []byte
	Wrapper           []byte
}{
	Ubi9Scan:          inspecUbi9Scan,
	ContainerScan:     inspecContainerScan,
	ThreeLayerOverlay: inspecThreeLayerOverlay,
	ThreeLayerRhel7:   inspecThreeLayerRhel7,
	Wrapper:           inspecWrapper,
}
