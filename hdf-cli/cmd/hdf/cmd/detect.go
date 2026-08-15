package cmd

import (
	"fmt"
	"strings"

	hdfengine "github.com/mitre/hdf-libs/hdf-engine/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
)

// detectHDFDocumentType fingerprints an HDF document by its root keys and
// returns the schema type string. Used by validate and diff for auto-detection
// when no explicit --type is provided. The fingerprinting itself lives in the
// cobra-free hdf-engine library so the CLI and the MCP share one implementation.
func detectHDFDocumentType(data []byte) string {
	return hdfengine.Detect(data)
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
	case string(validators.TypeRequirementChangeEvent):
		return "hdf events"
	default:
		return ""
	}
}
