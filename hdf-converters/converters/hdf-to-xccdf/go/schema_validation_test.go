package hdftoxccdf

import (
	"os"
	"path/filepath"
	"strconv"
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

// XCCDF types Group/@id as groupIdType: an NCName that must also match
// xccdf_[^_]+_group_.+ (xccdf_1.2.xsd:821). HDF puts no such constraint on
// tags.gid, and most real data does not satisfy it — 783 of the 1216 distinct
// gid values in this repo's fixtures are bare STIG ids like "V-257777", which
// the converter copied through to produce XSD-invalid output at exit 0. A gid
// that already conforms is a real STIG group id and is preserved as-is.
func TestConvertHDFToXCCDF_GroupIDsSatisfyXSD(t *testing.T) {
	v := xsdvalidate.New(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-xccdf", "schemas", "xccdf_1.2.xsd"))

	for _, tc := range []struct {
		gid  string
		want string
	}{
		{"V-257777", "xccdf_hdf_group_V-257777"},
		{"V-204393", "xccdf_hdf_group_V-204393"},
		{"SV-86603r1_rule", "xccdf_hdf_group_SV-86603r1_rule"},
		{"1.1.1 Ensure mounting is disabled", "xccdf_hdf_group_1.1.1_Ensure_mounting_is_disabled"},
		{"xccdf_mil.disa.stig_group_V-204393", "xccdf_mil.disa.stig_group_V-204393"},
	} {
		t.Run(tc.gid, func(t *testing.T) {
			// A timestamp is supplied so TestResult carries the end-time the XSD
			// requires; its absence is a separate defect tracked on its own card.
			input := []byte(`{"timestamp":"2020-01-01T00:00:00Z",` +
				`"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,` +
				`"tags":{"gid":` + strconv.Quote(tc.gid) + `},` +
				`"descriptions":[{"label":"default","data":"d"}],` +
				`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

			out, err := ConvertHDFToXCCDF(input, "1.0.0")
			require.NoError(t, err)
			v.RequireValid(t, tc.gid, out)
			require.Contains(t, string(out), `id="`+tc.want+`"`,
				"a conforming gid is preserved; a non-conforming one is encoded")
		})
	}
}

// benchmarkIdType and profileIdType require a trailing name segment via their
// .+ (xccdf_1.2.xsd:799, :843). A baseline with an empty name is valid HDF —
// the schema puts no minLength on it — but produced "xccdf_hdf_benchmark_",
// which the XSD rejects, so the converter emitted an invalid document at exit 0.
func TestConvertHDFToXCCDF_EmptyBaselineNameStillValid(t *testing.T) {
	v := xsdvalidate.New(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-xccdf", "schemas", "xccdf_1.2.xsd"))

	input := []byte(`{"timestamp":"2020-01-01T00:00:00Z",` +
		`"baselines":[{"name":"","requirements":[{"id":"r","impact":0,"tags":{},` +
		`"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

	out, err := ConvertHDFToXCCDF(input, "1.0.0")
	require.NoError(t, err)
	v.RequireValid(t, "empty baseline name", out)
	require.Contains(t, string(out), `id="xccdf_hdf_benchmark_unnamed"`)
	require.Contains(t, string(out), `id="xccdf_hdf_profile_unnamed"`)
}
