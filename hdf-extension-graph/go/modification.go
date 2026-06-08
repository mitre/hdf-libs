// Package hdfextension implements bidirectional extension graph processing for
// HDF profile/baseline hierarchies. It mirrors the @mitre/hdf-extension-graph
// TypeScript package: an HDF Results document is wrapped into a graph of
// contextualized baselines and requirements with parent/child links and
// derived properties (root, redundancy detection, full code assembly,
// extension chain, modification detection).
package hdfextension

// TrackedFields is the canonical list of EvaluatedRequirement field names
// whose changes Modifications detects, in the order Modifications emits them.
// Each field is a different type, so Modifications hardcodes one comparison
// per field rather than iterating this slice — TestTrackedFields pins the two
// lists to the same set and order so they cannot drift. The names match the
// JSON field names from the HDF schema (and the TypeScript package's
// TRACKED_FIELDS) so Modification.Field is stable across both implementations.
var TrackedFields = []string{
	"impact",
	"title",
	"severity",
	"effectiveImpact",
	"disposition",
}

// Modification is a detected change between an overlay requirement and its
// immediate parent on one of the TrackedFields.
//
// OriginalValue and NewValue hold the dereferenced field values (nil for
// absent pointer fields). For typed enum fields (Severity, Disposition) the
// stored value is the underlying string-backed enum value, which serializes
// identically to the TypeScript package's output.
type Modification struct {
	Field         string `json:"field"`
	OriginalValue any    `json:"originalValue"`
	NewValue      any    `json:"newValue"`
	InBaseline    string `json:"inBaseline"`
}
