package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The headless and from-vex routes validate their output against the
// hdf-amendments schema before writing; the interactive route did not, so a
// form-authored document that violates the schema was written silently and
// only failed later, at apply time or in a consumer. Validation belongs on the
// shared write path so all three routes give the identical guarantee.

func TestWriteAmendmentsOutput_RefusesSchemaInvalidDocument(t *testing.T) {
	// Missing the required `name`, and `overrides` is below minItems 1.
	invalid := map[string]interface{}{"overrides": []map[string]interface{}{}}

	path := filepath.Join(t.TempDir(), "amendments.json")
	err := writeAmendmentsOutput(invalid, path, 0, "waiver")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
	assert.NoFileExists(t, path, "a document that fails validation must not be written")
}

// stdout is an output too: emitting an invalid document there hands a consumer
// the same bad artifact through a pipe.
func TestWriteAmendmentsOutput_RefusesInvalidDocumentOnStdout(t *testing.T) {
	invalid := map[string]interface{}{"overrides": []map[string]interface{}{}}

	err := writeAmendmentsOutput(invalid, "", 0, "waiver")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
}

func TestWriteAmendmentsOutput_WritesValidInteractiveDocument(t *testing.T) {
	doc, err := buildAmendmentsFromOverrides([]amendOverride{
		{RequirementID: "AC-1", AmendType: "waiver", Reason: "Risk accepted",
			ExpiresAt: "2099-12-31", Approver: "issm@acme.com"},
	})
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "amendments.json")
	require.NoError(t, writeAmendmentsOutput(doc, path, 1, "waiver"))

	written, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	require.NoError(t, err)
	assert.Contains(t, string(written), "AC-1")
}
