package hdftoxccdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/xsdvalidate"
	"github.com/stretchr/testify/assert"
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
// gid values in this package's converter fixtures are bare STIG ids like "V-257777", which
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

// XCCDF makes TestResult/@end-time use="required" (xccdf_1.2.xsd:3131) while
// HDF's top-level timestamp is optional, so a schema-valid HDF document with no
// timestamp produced XCCDF missing a required attribute. Neither existing
// XSD-gated fixture omits the timestamp, so CI stayed green.
//
// The fallback is derived from the data, never the wall clock: a TestResult is
// emitted only when a baseline exists (buildBenchmark returns early otherwise),
// Evaluated_Baseline.requirements and Evaluated_Requirement.results both carry
// minItems 1, and Requirement_Result.startTime is required — so whenever an
// end-time is required, at least one result time exists to derive it from.
func TestConvertHDFToXCCDF_MissingTimestampStillValid(t *testing.T) {
	v := xsdvalidate.New(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-xccdf", "schemas", "xccdf_1.2.xsd"))
	hdfV := shared.NewSchemaValidator(t, filepath.Join("..", "..", "..", "..",
		"hdf-validators", "go", "schemas", "hdf-results.schema.json"))

	// Two results, deliberately out of chronological order, so the window is
	// derived by comparing times rather than by taking the first or last seen.
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,"tags":{},` +
		`"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-02T09:00:00Z"},` +
		`{"status":"failed","codeDesc":"c2","startTime":"2020-01-02T03:04:05Z"}]}]}]}`)

	require.NoError(t, hdfV.Validate(input), "the test input is not valid HDF")
	require.NotContains(t, string(input), `"timestamp"`, "this test is about the absent timestamp")

	out, err := ConvertHDFToXCCDF(input, "1.0.0")
	require.NoError(t, err)
	v.RequireValid(t, "missing timestamp", out)

	assert.Contains(t, string(out), `end-time="2020-01-02T09:00:00Z"`,
		"end-time must be the latest result time")
	assert.Contains(t, string(out), `start-time="2020-01-02T03:04:05Z"`,
		"start-time must be the earliest result time")
}

// An empty baselines array is valid HDF and emits no TestResult at all, so no
// end-time is required — the one shape where no result time exists.
func TestConvertHDFToXCCDF_NoBaselinesEmitsNoTestResult(t *testing.T) {
	v := xsdvalidate.New(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-xccdf", "schemas", "xccdf_1.2.xsd"))

	out, err := ConvertHDFToXCCDF([]byte(`{"baselines":[]}`), "1.0.0")
	require.NoError(t, err)
	v.RequireValid(t, "no baselines", out)
	assert.NotContains(t, string(out), "<TestResult")
}

// Every timestamp this converter emits is HDF's canonical form: RFC3339 in UTC
// with trailing fractional zeros trimmed. TypeScript used to pass the source
// string through instead, so a result time of ".500Z" emitted ".500Z" there and
// ".5Z" here — a divergence no fixture happened to carry.
func TestConvertHDFToXCCDF_TimestampsAreCanonical(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,"tags":{},` +
		`"descriptions":[{"label":"default","data":"d"}],"results":[` +
		`{"status":"passed","codeDesc":"c","startTime":"2020-01-02T09:00:00.500Z"},` +
		`{"status":"failed","codeDesc":"c2","startTime":"2020-01-02T03:04:05.120Z"},` +
		`{"status":"passed","codeDesc":"c3","startTime":"2020-01-02T07:30:00.000Z"}]}]}]}`)

	out, err := ConvertHDFToXCCDF(input, "1.0.0")
	require.NoError(t, err)

	s := string(out)
	assert.Contains(t, s, `start-time="2020-01-02T03:04:05.12Z"`)
	assert.Contains(t, s, `end-time="2020-01-02T09:00:00.5Z"`)
	assert.Contains(t, s, `time="2020-01-02T07:30:00Z"`, "an all-zero fraction is dropped entirely")
	assert.NotContains(t, s, ".500Z")
	assert.NotContains(t, s, ".120Z")
	assert.NotContains(t, s, ".000Z")
}

// The two languages guarded the InSpec <check> differently: Go emitted one
// whenever code was non-nil, so an empty string produced an empty check element,
// while TypeScript's truthy test skipped it. Both now use the shared
// non-empty-text helper, so whitespace-only code is skipped too rather than
// trading one divergence for another.
func TestConvertHDFToXCCDF_InspecCheckOnlyForRealCode(t *testing.T) {
	const inspec = `system="http://inspec.io/"`

	for _, tc := range []struct {
		name string
		code string // raw JSON for the code field, or "" to omit it
		want bool
	}{
		{"absent", "", false},
		{"empty", `"code":"",`, false},
		{"whitespace only", `"code":"   ",`, false},
		{"real code", `"code":"describe file('/etc/passwd') do\n end",`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(`{"baselines":[{"name":"b","requirements":[{"id":"r","impact":0,"tags":{},` +
				tc.code +
				`"descriptions":[{"label":"default","data":"d"}],` +
				`"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}`)

			out, err := ConvertHDFToXCCDF(input, "1.0.0")
			require.NoError(t, err)
			assert.Equal(t, tc.want, strings.Contains(string(out), inspec),
				"an InSpec check is emitted only for code that carries text")
		})
	}
}

// TestConvertHDFToXCCDF_AdversarialCorpus holds this converter to the shared
// corpus contracts. The corpus harness takes any DocumentValidator, so an
// XSD-backed converter runs the same cases as the JSON-schema ones.
func TestConvertHDFToXCCDF_AdversarialCorpus(t *testing.T) {
	v := xsdvalidate.New(t, filepath.Join(shared.GetConvertersDir(),
		"hdf-to-xccdf", "schemas", "xccdf_1.2.xsd"))

	shared.RunSchemaCorpus(t, v, shared.ResultsCorpus(), func(in []byte) ([]byte, error) {
		return ConvertHDFToXCCDF(in, "1.0.0")
	})
}

// corpusRejected marks a corpus case the converter refuses. The two languages
// phrase the error differently, so only the fact of refusing is compared.
const corpusRejected = "REJECTED"

// TestConvertHDFToXCCDF_CorpusOutputGolden pins what this converter emits for
// every corpus input, in the normalized form both languages compare goldens in.
//
// Running the corpus in each language proves each satisfies the XSD, which is
// not the same as proving they agree: TypeScript once wrote the literal string
// "undefined" into a rule id where Go wrote nothing, and both forms satisfied
// the pattern, so neither XSD gate noticed. The only parity gate before this was
// two fully-populated fixture goldens, which no adversarial shape reaches.
//
// Go owns regeneration (go test ./converters/hdf-to-xccdf/go/ -update) and
// TypeScript only verifies, so neither side can quietly redefine parity to match
// itself.
func TestConvertHDFToXCCDF_CorpusOutputGolden(t *testing.T) {
	outputs := make(map[string]string, len(shared.ResultsCorpus()))
	for _, c := range shared.ResultsCorpus() {
		out, err := ConvertHDFToXCCDF(c.Input, "1.0.0")
		if err != nil {
			outputs[c.Name] = corpusRejected
			continue
		}
		outputs[c.Name] = shared.NormalizeXMLForGolden(string(out))
	}

	actual, err := json.MarshalIndent(outputs, "", "  ")
	require.NoError(t, err)
	actual = append(actual, '\n')

	path := filepath.Join("..", "fixtures", "expected", "corpus-outputs.json")
	if shared.UpdateSnapshots() {
		require.NoError(t, os.WriteFile(path, actual, 0o600))
		t.Logf("updated %s", path)
		return
	}

	expected, err := os.ReadFile(path)
	require.NoError(t, err, "missing corpus output golden; regenerate with -update")
	require.JSONEq(t, string(expected), string(actual),
		"corpus output changed; if intentional regenerate with: go test ./converters/hdf-to-xccdf/go/ -update")
}
