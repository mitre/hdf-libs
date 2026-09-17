package hdfengine

import (
	"encoding/json"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// Detect fingerprints an HDF document by its root keys and returns the schema
// type string (a validators.Type* value), or "" when the input is not JSON or
// matches no known HDF document type. Relocated verbatim from the CLI's
// former internal/hdfdetect package (ADR-0007 engine-library revision) so both
// the CLI and the MCP can classify documents from the shared engine library.
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

	// This is the SINGLE HDF fingerprinter for the CLI and MCP — the former
	// CLI-local root-key detector was removed in favor of it, so all callers
	// share one precedence and one vocabulary (validators.Type*).
	//
	// Precedence is most-specific-first: a document that carries several root
	// keys is classified by the more distinctive one. `contents` (evidence
	// package), `overrides` (amendments) and `assessments` (plan) are each unique
	// to one type and win over the broader `baselines`/`components`/`requirements`.
	// Comparison is identified by EITHER `comparisonMode` (the canonical semantic
	// discriminator) OR `requirementDiffs` — the schema requires both, so a doc
	// carrying only one is a malformed comparison, and matching on either routes it
	// to the comparison validator (which fails it loudly) instead of letting it fall
	// through to "" and skip validation entirely.
	switch {
	case hasKeys(doc, "contents"):
		return string(validators.TypeEvidencePackage)
	case hasKeys(doc, "overrides"):
		return string(validators.TypeAmendments)
	case hasKeys(doc, "assessments"):
		return string(validators.TypePlan)
	case hasKeys(doc, "comparisonMode"), hasKeys(doc, "requirementDiffs"):
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

// KnownTypes returns the HDF document types Detect can recognize, in schema-id
// order — the recognized-type set an "unrecognized document" diagnostic should
// name. Kept beside Detect so the two move together; TestKnownTypes_MatchesDetect
// guards that every entry here is actually detectable.
func KnownTypes() []string {
	return []string{
		string(validators.TypeResults),
		string(validators.TypeBaseline),
		string(validators.TypeSystem),
		string(validators.TypePlan),
		string(validators.TypeAmendments),
		string(validators.TypeEvidencePackage),
		string(validators.TypeComparison),
		string(validators.TypeRequirementChangeEvent),
	}
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
