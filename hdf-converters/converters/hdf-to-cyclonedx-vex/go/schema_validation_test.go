package hdftocyclonedxvex

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/require"
)

// TestConvertHDFToCycloneDXVEX_SchemaValid gates the converter output on the
// CycloneDX v1.4 BOM JSON schema (draft-07). The bom schema $refs the SPDX and
// JSF schemas; both are vendored alongside it and registered as companions under
// their $ids so it compiles offline.
func TestConvertHDFToCycloneDXVEX_SchemaValid(t *testing.T) {
	schemas := filepath.Join(shared.GetConvertersDir(), "hdf-to-cyclonedx-vex", "schemas")
	v := shared.NewSchemaValidatorWithResources(t,
		filepath.Join(schemas, "bom-1.4.schema.json"),
		map[string]string{
			"http://cyclonedx.org/schema/spdx.schema.json":     filepath.Join(schemas, "spdx.schema.json"),
			"http://cyclonedx.org/schema/jsf-0.82.schema.json": filepath.Join(schemas, "jsf-0.82.schema.json"),
		})

	for _, name := range []string{"case1-fixed-amendments.json", "case1-not_affected-amendments.json"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
			require.NoError(t, err)
			out, err := ConvertHDFToCycloneDXVEX(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, name, out)
		})
	}
}
