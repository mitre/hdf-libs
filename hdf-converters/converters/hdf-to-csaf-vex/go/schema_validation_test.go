package hdftocsafvex

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToCSAFVEX_SchemaValid gates the converter output on the OASIS
// CSAF v2.0 JSON schema (draft 2020-12). The CSAF schema $refs the FIRST.org
// CVSS schemas by URL; those are vendored alongside it and registered as
// companions so it compiles offline.
func TestConvertHDFToCSAFVEX_SchemaValid(t *testing.T) {
	base := filepath.Join(shared.GetConvertersDir(), "csaf-vex-to-hdf", "fixtures")
	v := shared.NewSchemaValidatorWithResources(t,
		filepath.Join(base, "csaf_json_schema.json"),
		map[string]string{
			"https://www.first.org/cvss/cvss-v2.0.json": filepath.Join(base, "cvss-v2.0.json"),
			"https://www.first.org/cvss/cvss-v3.0.json": filepath.Join(base, "cvss-v3.0.json"),
			"https://www.first.org/cvss/cvss-v3.1.json": filepath.Join(base, "cvss-v3.1.json"),
		})

	for _, name := range []string{"sec-vex-amendments.json"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
			require.NoError(t, err)
			out, err := ConvertHDFToCSAFVEX(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, name, out)
		})
	}
}
