package cmd

import (
	"os"
	"path/filepath"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/require"
)

// TestLoadAndValidateHDFDoc_UsesCanonicalType covers ecrzs: the CLI must have a
// single fingerprinter (hdfengine.Detect) with one vocabulary. The former local
// detectHDFDocType returned the camelCase "evidencePackage"; the canonical value
// is validators.TypeEvidencePackage ("evidence-package"), which Detect returns.
// Passing the canonical type string must classify an evidence-package document.
func TestLoadAndValidateHDFDoc_UsesCanonicalType(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "evidence-verify", "evidence.json"))
	require.NoError(t, err)

	_, err = loadAndValidateHDFDoc(data, string(validators.TypeEvidencePackage))
	require.NoError(t, err,
		"an evidence-package doc must classify under the canonical type string %q",
		validators.TypeEvidencePackage)
}
