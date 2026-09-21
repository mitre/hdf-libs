package hdftocyclonedxvex

import (
	"os"
	"path/filepath"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/require"
)

// cdxValidator compiles the CycloneDX v1.4 BOM JSON schema (draft-07). The bom
// schema $refs the SPDX and JSF schemas; both are vendored alongside it and
// registered as companions under their $ids so it compiles offline.
func cdxValidator(t *testing.T) *shared.SchemaValidator {
	t.Helper()
	schemas := filepath.Join(shared.GetConvertersDir(), "hdf-to-cyclonedx-vex", "schemas")
	return shared.NewSchemaValidatorWithResources(t,
		filepath.Join(schemas, "bom-1.4.schema.json"),
		map[string]string{
			"http://cyclonedx.org/schema/spdx.schema.json":     filepath.Join(schemas, "spdx.schema.json"),
			"http://cyclonedx.org/schema/jsf-0.82.schema.json": filepath.Join(schemas, "jsf-0.82.schema.json"),
		})
}

// TestConvertHDFToCycloneDXVEX_SchemaValid gates the converter output on the
// CycloneDX v1.4 BOM JSON schema for the golden fixtures.
func TestConvertHDFToCycloneDXVEX_SchemaValid(t *testing.T) {
	v := cdxValidator(t)

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

// TestConvertHDFToCycloneDXVEX_AdversarialCorpus runs the shared corpus, so this
// converter is held to both contracts an exporter owes rather than only to
// fully-populated fixtures. Every MustConvert case names no product, which is the
// path the happy-path fixtures never reach.
func TestConvertHDFToCycloneDXVEX_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, cdxValidator(t), corpus.AmendmentsCorpus(), func(in []byte) ([]byte, error) {
		return ConvertHDFToCycloneDXVEX(in, "1.0.0")
	})
}

// TestCorpusGoldenParity freezes this converter's output for every MustConvert
// corpus case, and the TypeScript suite asserts against the SAME files. The corpus
// exercises the sparse inputs where the two implementations are most likely to
// drift; every value is deterministic, so the comparison is byte-for-byte.
func TestCorpusGoldenParity(t *testing.T) {
	for _, c := range corpus.AmendmentsCorpus() {
		if c.Contract != corpus.MustConvert {
			continue // anything else may be rejected, so there is no output to freeze
		}
		t.Run(c.Name, func(t *testing.T) {
			out, err := ConvertHDFToCycloneDXVEX(c.Input, "1.0.0")
			require.NoError(t, err)

			goldenPath := filepath.Join(shared.GetConvertersDir(), "hdf-to-cyclonedx-vex",
				"fixtures", "expected", "corpus-"+c.Name+".cdx.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
				return
			}

			golden, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "read golden %s (regenerate with UPDATE_GOLDEN=1)", goldenPath)
			require.Equal(t, string(golden), string(out), "golden mismatch for %s", c.Name)
			require.NotContains(t, string(out), "HDFPID",
				"a synthetic product id asserts traceability the source never had")
		})
	}
}
