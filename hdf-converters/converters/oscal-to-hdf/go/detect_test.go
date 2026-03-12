package oscal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectDocumentType(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		expected string
	}{
		{"SAR", "../fixtures/input/sar-fedramp.json", "assessment-results"},
		{"SAP", "../fixtures/input/sap-fedramp.json", "assessment-plan"},
		{"SSP example", "../fixtures/input/ssp-example.json", "system-security-plan"},
		{"SSP FedRAMP", "../fixtures/input/ssp-fedramp.json", "system-security-plan"},
		{"POA&M", "../fixtures/input/poam-fedramp.json", "plan-of-action-and-milestones"},
		{"Catalog", "../fixtures/input/catalog-800-53-rev5.json", "catalog"},
		{"Profile", "../fixtures/input/profile-moderate.json", "profile"},
		{"Component", "../fixtures/input/component-example.json", "component-definition"},
		{"Resolved catalog", "../fixtures/input/catalog-moderate-resolved.json", "catalog"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := os.ReadFile(tt.file)
			require.NoError(t, err)

			docType, err := DetectDocumentType(input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, docType)
		})
	}
}

func TestDetectDocumentType_InvalidInput(t *testing.T) {
	_, err := DetectDocumentType([]byte(`not json`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")

	_, err = DetectDocumentType([]byte(`{"unknown-root": {}}`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized OSCAL document")
}

func TestOscalDocument_DocumentType(t *testing.T) {
	doc := &OscalDocument{}
	assert.Equal(t, "", doc.DocumentType())

	doc.Catalog = &Catalog{}
	assert.Equal(t, "catalog", doc.DocumentType())
}
