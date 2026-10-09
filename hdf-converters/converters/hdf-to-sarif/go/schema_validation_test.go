package hdftosarif

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	testhdf "github.com/mitre/hdf-libs/hdf-schema/testhdf/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

// sarifSchema loads the SARIF 2.1.0 schema vendored for sarif-to-hdf. There is
// one vendored copy in the repo and both directions validate against it.
//
// Read as bytes rather than through a file:// reference loader: a Windows
// absolute path ("D:\...") produces a malformed file:// URI and fails on
// windows-latest CI. NewBytesLoader sidesteps URI parsing entirely.
func sarifSchema(t *testing.T) *gojsonschema.Schema {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "sarif-schema-2.1.0.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- repo-relative vendored schema
	require.NoError(t, err, "read vendored SARIF schema")
	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(raw))
	require.NoError(t, err, "compile vendored SARIF schema")
	return schema
}

// requireValidSARIF reports every violation when a document fails, so a red run
// names what is wrong instead of only that something is.
func requireValidSARIF(t *testing.T, schema *gojsonschema.Schema, label string, doc []byte) {
	t.Helper()
	result, err := schema.Validate(gojsonschema.NewBytesLoader(doc))
	require.NoError(t, err, "%s: load output for validation", label)
	if result.Valid() {
		return
	}
	for _, e := range result.Errors() {
		t.Errorf("%s: %s", label, e)
	}
	t.Fatalf("%s: output does not satisfy SARIF 2.1.0", label)
}

func TestConvertHDFToSARIF_ValidatesAgainstTheVendoredSchema(t *testing.T) {
	schema := sarifSchema(t)
	// Exactly the golden inputs, so no frozen golden escapes the schema.
	for _, name := range goldenInputs {
		out, err := ConvertHDFToSARIF(loadGoldenInput(t, name), testVersion)
		require.NoError(t, err)
		require.NotEmpty(t, out)
		requireValidSARIF(t, schema, name, out)
	}
}

// The big real documents are validated but not frozen: a golden for a 16-baseline
// Prisma export or a 26-finding Grype scan would be hundreds of kilobytes of
// review noise, while schema validity and the run count are what they prove.
func TestConvertHDFToSARIF_ValidatesLargeRealDocuments(t *testing.T) {
	schema := sarifSchema(t)
	for _, c := range []struct {
		name  string
		input []byte
		runs  int
	}{
		{"hdf-fixtures results/duplicate-baselines.json", fixtures.Results.DuplicateBaselines, 16},
		{"hdf-fixtures results/merge-grype.json", fixtures.Results.MergeGrype, 1},
		{"hdf-fixtures results/merge-zap.json", fixtures.Results.MergeZap, 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := ConvertHDFToSARIF(c.input, testVersion)
			require.NoError(t, err)
			requireValidSARIF(t, schema, c.name, out)

			var log struct {
				Runs []json.RawMessage `json:"runs"`
			}
			require.NoError(t, json.Unmarshal(out, &log))
			assert.Len(t, log.Runs, c.runs, "one run per baseline")
		})
	}
}

// sarifValidator adapts the compiled schema to the corpus harness's contract.
type sarifValidator struct {
	t      *testing.T
	schema *gojsonschema.Schema
}

func (v sarifValidator) Validate(doc []byte) error {
	v.t.Helper()
	result, err := v.schema.Validate(gojsonschema.NewBytesLoader(doc))
	if err != nil {
		return err
	}
	if result.Valid() {
		return nil
	}
	msgs := make([]string, 0, len(result.Errors()))
	for _, e := range result.Errors() {
		msgs = append(msgs, e.String())
	}
	return errors.New(strings.Join(msgs, "\n"))
}

// TestConvertHDFToSARIF_AdversarialCorpus holds this converter to the shared
// corpus contracts with no exemptions: SARIF models a log with no runs, so even
// the zero-baselines case that a checklist cannot represent converts here.
func TestConvertHDFToSARIF_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, sarifValidator{t: t, schema: sarifSchema(t)}, corpus.ResultsCorpus(),
		func(in []byte) ([]byte, error) { return ConvertHDFToSARIF(in, testVersion) })
}

// Every SARIF result this exporter emits is re-derived from the mapped HDF
// fields. It never replays rawSourceRecord, whose bytes are the converter's
// input: a byte-replay would make a round-trip test pass while proving nothing
// about the field mapping, and would silently re-emit the pre-amendment finding
// for any document amended after import.
func TestConvertHDFToSARIF_DoesNotReplayTheRawSourceRecord(t *testing.T) {
	// A stale record that disagrees with every mapped field it duplicates.
	stale := `{"ruleId":"STALE","level":"none","kind":"pass","message":{"text":"stale bytes"}}`
	doc := testhdf.Results(testhdf.Req("V-1",
		testhdf.Status(hdf.Failed), testhdf.Impact(0.7), testhdf.CodeDesc("the mapped message")))
	doc.Baselines[0].Requirements[0].Results[0].RawSourceRecord = &hdf.RawSourceRecord{
		Content:   stale,
		Encoding:  "utf-8",
		MediaType: "application/json",
	}

	input, err := json.Marshal(doc)
	require.NoError(t, err)
	out, err := ConvertHDFToSARIF(input, testVersion)
	require.NoError(t, err)

	assert.NotContains(t, string(out), "stale bytes",
		"the native record's bytes must not reach the output, not even inside a property bag")
	assert.NotContains(t, string(out), "rawSourceRecord")

	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &log))
	res := result0(t, log)
	assert.Equal(t, "V-1", res["ruleId"], "the id comes from the HDF field, not the stored bytes")
	assert.Equal(t, "fail", res["kind"])
	assert.Equal(t, "error", res["level"])
	msg, _ := res["message"].(map[string]interface{})
	assert.Equal(t, "the mapped message", msg["text"])
}

// rawSourceArtifacts holds the bytes the document was converted FROM. Echoing a
// whole source artifact back would multiply the output and invite the same
// byte-replay shortcut.
func TestConvertHDFToSARIF_DoesNotEchoRawSourceArtifacts(t *testing.T) {
	input := []byte(`{"baselines":[{"name":"b","requirements":[` +
		`{"id":"V-1","impact":0.5,"tags":{},"descriptions":[{"label":"default","data":"d"}],` +
		`"results":[{"status":"failed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}],` +
		`"extensions":{"passthrough":{"vendor":{"keep":"me"}},` +
		`"rawSourceArtifacts":[{"rel":"raw-source","sourceName":"Flawfinder",` +
		`"mediaType":"application/sarif+json","encoding":"utf-8","content":"SOURCE-ARTIFACT-BYTES"}]}}`)
	out, err := ConvertHDFToSARIF(input, testVersion)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "SOURCE-ARTIFACT-BYTES")
	assert.NotContains(t, string(out), "rawSourceArtifacts")

	var log map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &log))
	block, _ := props(t, log)[hdfBagKey].(map[string]interface{})
	ext, _ := block["extensions"].(map[string]interface{})
	passthrough, _ := ext["passthrough"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"keep": "me"}, passthrough["vendor"],
		"producer data in passthrough is carried; only the source artifact is dropped")
}
