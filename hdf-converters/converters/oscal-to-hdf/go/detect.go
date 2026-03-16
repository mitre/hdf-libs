package oscal

import (
	"encoding/json"
	"fmt"
)

// DetectDocumentType parses the input JSON just enough to determine which
// OSCAL document type it contains. Returns one of the 7 OSCAL root key
// strings, or an error if the input is not valid OSCAL.
func DetectDocumentType(input []byte) (string, error) {
	var doc OscalDocument
	if err := json.Unmarshal(input, &doc); err != nil {
		return "", fmt.Errorf("failed to parse OSCAL document: %w", err)
	}

	docType := doc.DocumentType()
	if docType == "" {
		return "", fmt.Errorf("unrecognized OSCAL document: expected one of catalog, profile, component-definition, system-security-plan, assessment-plan, assessment-results, plan-of-action-and-milestones as root key")
	}

	return docType, nil
}
