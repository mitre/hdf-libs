package cmd

import (
	"encoding/json"

	validators "github.com/mitre/hdf-validators/go"
)

// detectHDFDocumentType fingerprints an HDF document by its root keys
// and returns the schema type string. Used by validate and info for
// auto-detection when no explicit --type is provided.
func detectHDFDocumentType(data []byte) string {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return string(validators.TypeResults)
	}

	// Most specific first — check for key combinations unique to each type
	if _, ok := doc["contents"]; ok {
		return string(validators.TypeEvidencePackage)
	}
	if _, ok := doc["overrides"]; ok {
		return string(validators.TypeAmendments)
	}
	if _, ok := doc["assessments"]; ok {
		return string(validators.TypePlan)
	}
	if _, ok := doc["comparisonMode"]; ok {
		return string(validators.TypeComparison)
	}
	// Results have baselines; systems have components but not baselines
	if _, ok := doc["baselines"]; ok {
		return string(validators.TypeResults)
	}
	if _, ok := doc["components"]; ok {
		return string(validators.TypeSystem)
	}
	if _, ok := doc["requirements"]; ok {
		return string(validators.TypeBaseline)
	}
	return string(validators.TypeResults)
}
