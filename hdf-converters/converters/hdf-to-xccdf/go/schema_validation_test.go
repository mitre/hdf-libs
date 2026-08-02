package hdftoxccdf

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/xsdvalidate"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToXCCDF_SchemaValid gates the converter output on the NIST
// XCCDF 1.2 XSD. The XSD imports xml.xsd and the CPE 2.3 schemas; all are
// vendored alongside it with local schemaLocations so it compiles offline.
// See ../schemas/PROVENANCE.md.
func TestConvertHDFToXCCDF_SchemaValid(t *testing.T) {
	v := xsdvalidate.New(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-xccdf", "schemas", "xccdf_1.2.xsd"))

	for _, name := range []string{"minimal.json", "stig-rhel7.json"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
			require.NoError(t, err)
			out, err := ConvertHDFToXCCDF(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, name, out)
		})
	}
}
