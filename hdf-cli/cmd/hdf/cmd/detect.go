package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	validators "github.com/mitre/hdf-libs/hdf-validators/go"
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

// requireDocumentType reads raw JSON, detects its type, and returns an error
// if the type is not in the allowed set. The error message names the actual
// type and suggests an alternative command when possible.
func requireDocumentType(data []byte, allowed []string, cmdName string) (string, error) {
	actual := detectHDFDocumentType(data)

	for _, a := range allowed {
		if actual == a {
			return actual, nil
		}
	}

	suggestion := suggestCommand(actual)
	hint := ""
	if suggestion != "" {
		hint = fmt.Sprintf("\n  Try: %s", suggestion)
	}

	return actual, fmt.Errorf(
		"%s requires %s, but this is %s%s",
		cmdName, formatAllowed(allowed), articleFor(actual), hint,
	)
}

// formatAllowed joins type names with "or" for error messages.
func formatAllowed(types []string) string {
	switch len(types) {
	case 1:
		return articleFor(types[0])
	case 2: //nolint:mnd // natural language formatting
		return articleFor(types[0]) + " or " + articleFor(types[1])
	default:
		parts := make([]string, len(types))
		for i, t := range types {
			parts[i] = articleFor(t)
		}
		return strings.Join(parts[:len(parts)-1], ", ") + ", or " + parts[len(parts)-1]
	}
}

// articleFor returns "a/an <type> document" with correct article.
func articleFor(docType string) string {
	switch docType {
	case "amendments", "evidence-package":
		return "an " + docType + " document"
	default:
		return "a " + docType + " document"
	}
}

// suggestCommand returns a hint for what command to use for a given document type.
func suggestCommand(docType string) string {
	switch docType {
	case string(validators.TypeResults):
		return "hdf list, hdf query, or hdf diff"
	case string(validators.TypeSystem):
		return "hdf system info"
	case string(validators.TypeAmendments):
		return "hdf amend list"
	case string(validators.TypeBaseline):
		return "hdf validate --type baseline"
	case string(validators.TypePlan):
		return "hdf plan"
	case string(validators.TypeEvidencePackage):
		return "hdf evidence"
	default:
		return ""
	}
}
