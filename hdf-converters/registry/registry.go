// Package registry provides a self-registering fingerprint system for
// converter auto-detection. Each converter registers a lightweight
// structural fingerprint; the dispatcher walks the registry to find
// the highest-confidence match for a given input.
package registry

// InputFamily represents the broad format category of converter input.
type InputFamily string

const (
	FamilyJSON InputFamily = "json"
	FamilyXML  InputFamily = "xml"
	FamilyText InputFamily = "text"
)

// Direction indicates whether a converter ingests or exports.
type Direction string

const (
	DirectionIngest Direction = "ingest"
	DirectionExport Direction = "export"
)

// OutputType indicates what HDF document type the converter produces.
type OutputType string

const (
	OutputResults     OutputType = "results"
	OutputBaseline    OutputType = "baseline"
	OutputPlan        OutputType = "plan"
	OutputAmendments  OutputType = "amendments"
	OutputSystem      OutputType = "system"
	OutputEvidencePkg OutputType = "evidence-package"
	OutputRaw         OutputType = "raw"
)

// ConverterFingerprint is lightweight metadata for format detection.
// It does NOT include the convert function — converters are loaded separately.
type ConverterFingerprint struct {
	ID          string
	Label       string
	Direction   Direction
	InputFamily InputFamily
	OutputType  OutputType
	// Fingerprint returns a confidence score 0.0-1.0 for the given input.
	// JSON input is passed as map[string]any or []any.
	// XML/text input is passed as string.
	Fingerprint func(input any) float64
	// DetectVersion optionally returns a version string from the parsed input.
	// For example, SARIF returns obj["version"] ("2.1.0"), CycloneDX returns
	// obj["specVersion"] ("1.5"). Nil means the fingerprint does not detect
	// versions and DetectionResult.Version will be empty.
	DetectVersion func(input any) string
}

var registry []ConverterFingerprint

// Register adds a fingerprint to the registry. Panics on duplicate ID.
// Must only be called from init() functions or before any concurrent reads.
func Register(fp ConverterFingerprint) {
	for _, existing := range registry {
		if existing.ID == fp.ID {
			panic("duplicate fingerprint: " + fp.ID)
		}
	}
	registry = append(registry, fp)
}

// GetFingerprints returns a copy of all registered fingerprints.
// The returned slice is safe to iterate without affecting the registry.
func GetFingerprints() []ConverterFingerprint {
	return append([]ConverterFingerprint{}, registry...)
}

// GetIngestFingerprints returns only ingest-direction fingerprints.
func GetIngestFingerprints() []ConverterFingerprint {
	var result []ConverterFingerprint
	for _, fp := range registry {
		if fp.Direction == DirectionIngest {
			result = append(result, fp)
		}
	}
	return result
}

// GetFingerprint returns a fingerprint by ID, or nil if not found.
// Returns a copy to prevent callers from mutating the registry.
func GetFingerprint(id string) *ConverterFingerprint {
	for i := range registry {
		if registry[i].ID == id {
			fp := registry[i]
			return &fp
		}
	}
	return nil
}

// ResetRegistry clears all registered fingerprints. For testing only.
func ResetRegistry() {
	registry = nil
}
