package hdftoopenvex

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToOpenVEX_SchemaValid gates the converter output on the OpenVEX
// v0.2.0 JSON schema (draft 2020-12). See the vendored schema under
// openvex-to-hdf/fixtures.
func TestConvertHDFToOpenVEX_SchemaValid(t *testing.T) {
	v := shared.NewSchemaValidator(t, filepath.Join(shared.GetConvertersDir(),
		"openvex-to-hdf", "fixtures", "openvex_json_schema.json"))

	for _, name := range []string{"multi-status-amendments.json", "spring-boot-log4j-amendments.json"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
			require.NoError(t, err)
			out, err := ConvertHDFToOpenVEX(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, name, out)
		})
	}
}
