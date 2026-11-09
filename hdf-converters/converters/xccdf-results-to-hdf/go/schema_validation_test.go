package xccdf

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/xsdvalidate"
	"github.com/stretchr/testify/require"
)

// TestInputsAreSchemaValid gates the authored inputs on the NIST XCCDF 1.2 XSD
// vendored under hdf-to-xccdf/schemas. The captured tool outputs need no gate —
// a real scanner's document is its own evidence — but an authored one is only
// admissible as a fixture if the format admits its shape, so the check belongs
// in the suite rather than in a one-off run recorded in prose.
func TestInputsAreSchemaValid(t *testing.T) {
	v := xsdvalidate.New(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-xccdf", "schemas", "xccdf_1.2.xsd"))

	for _, name := range []string{"rule-result-dispositions.xml"} {
		t.Run(name, func(t *testing.T) {
			doc, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
			require.NoError(t, err)
			v.RequireValid(t, name, doc)
		})
	}
}
