// Package hdfdetect fingerprints an HDF document by its root keys and returns
// the schema type string. It has no cobra or CLI dependencies, so non-CLI
// consumers (such as the MCP document loader) can classify HDF documents
// without importing package cmd.
package hdfdetect

import (
	"encoding/json"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// Detect fingerprints an HDF document by its root keys and returns the schema
// type string (a validators.Type* value), or "" when the input is not JSON or
// matches no known HDF document type.
func Detect(data []byte) string {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return ""
	}

	// Most specific first. A requirement-change-event carries the singular
	// requirementId together with the state/before/after triad — a combination
	// no other HDF document type has — so it is checked ahead of the rest.
	if hasKeys(doc, "requirementId", "state", "before", "after") {
		return string(validators.TypeRequirementChangeEvent)
	}

	switch {
	case hasKeys(doc, "contents"):
		return string(validators.TypeEvidencePackage)
	case hasKeys(doc, "overrides"):
		return string(validators.TypeAmendments)
	case hasKeys(doc, "assessments"):
		return string(validators.TypePlan)
	case hasKeys(doc, "comparisonMode"):
		return string(validators.TypeComparison)
	case hasKeys(doc, "baselines"):
		return string(validators.TypeResults)
	case hasKeys(doc, "components"):
		return string(validators.TypeSystem)
	case hasKeys(doc, "requirements"):
		return string(validators.TypeBaseline)
	}
	return ""
}

// hasKeys reports whether every named key is present at the document root.
func hasKeys(doc map[string]json.RawMessage, keys ...string) bool {
	for _, k := range keys {
		if _, ok := doc[k]; !ok {
			return false
		}
	}
	return true
}
