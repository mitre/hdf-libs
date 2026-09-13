package hdftocklb

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/checklist"
	"github.com/stretchr/testify/require"
)

// NO PUBLISHED SCHEMA FOR .cklb. Searched 2026-09-09 (recorded in
// ../schemas/provenance.txt): DISA documents the format in the STIG Viewer 3.x
// user guide, a PDF, and publishes nothing machine-readable. So the conformance
// check available here is a round trip: output this repo's own ParseCKLB cannot
// read back is malformed in the way a schema would catch.
type cklbRoundTripValidator struct{}

func (cklbRoundTripValidator) Validate(doc []byte) error {
	if len(doc) == 0 {
		return nil
	}
	cl, err := checklist.ParseCKLB(doc)
	if err != nil {
		return fmt.Errorf("output does not re-import through ParseCKLB: %w", err)
	}
	if cl == nil {
		return fmt.Errorf("ParseCKLB returned no checklist for non-empty output")
	}
	return nil
}

// corpusExemptions mirrors hdf-to-ckl's: only zero-baselines remains, and it is
// a deliberate, permanent rejection. It is pinned below.
var corpusExemptions = map[string]string{
	"zero-baselines": "baselines has no minItems, so an assessment that evaluated nothing is legal HDF a checklist cannot represent — rejected deliberately, matching hdf-to-ckl and hdf-to-oscal-sar",
}

func corpusMinusExemptions(t *testing.T) []corpus.CorpusCase {
	t.Helper()
	kept := make([]corpus.CorpusCase, 0)
	for _, c := range corpus.ResultsCorpus() {
		if reason, skipped := corpusExemptions[c.Name]; skipped {
			t.Logf("corpus case %q exempted — %s", c.Name, reason)
			continue
		}
		kept = append(kept, c)
	}
	require.NotEmpty(t, kept, "every case exempted — the run would prove nothing")
	return kept
}

// TestConvertHDFToCKLB_AdversarialCorpus holds this converter to the shared
// corpus contracts, with the round trip standing in for the schema DISA does not
// publish.
func TestConvertHDFToCKLB_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, cklbRoundTripValidator{}, corpusMinusExemptions(t), ConvertHDFToCKLB)
}

// The zero-baselines exemption above claims a deliberate rejection. hdf-to-oscal-sar
// backs its identical exemption with a pin; without one here the exemption could
// silently become a real hole, so this asserts the rejection actually happens.
func TestConvertHDFToCKLB_RejectsZeroBaselines(t *testing.T) {
	_, exempted := corpusExemptions["zero-baselines"]
	require.True(t, exempted, "this pin only means something while the case is exempted")

	_, err := ConvertHDFToCKLB([]byte(`{"baselines":[],"generator":{"name":"x","version":"1"},` +
		`"timestamp":"2020-01-01T00:00:00Z"}`))
	require.Error(t, err, "zero baselines must be rejected, not converted into an empty checklist")
}

// corpusRejected marks a corpus case the converter refuses; the two languages
// must agree on rejection as well as on output.
const corpusRejected = "REJECTED"

// Pins what this converter emits for every corpus input so the two languages are
// compared against one another rather than each against its own expectations.
// Go owns regeneration (go test ./converters/hdf-to-cklb/go/ -update); TypeScript only
// verifies. This is what makes the byte-identical claim an assertion.
func TestConvertHDFToCKLB_CorpusOutputGolden(t *testing.T) {
	outputs := make(map[string]string, len(corpus.ResultsCorpus()))
	for _, c := range corpus.ResultsCorpus() {
		out, err := corpus.ConvertNoPanic(ConvertHDFToCKLB, c.Input)
		if err != nil {
			outputs[c.Name] = corpusRejected
			continue
		}
		outputs[c.Name] = string(out)
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
	expected, err := os.ReadFile(path) // #nosec G304 -- repo-relative golden
	require.NoError(t, err, "missing corpus output golden; regenerate with -update")
	require.JSONEq(t, string(expected), string(actual),
		"corpus output changed; if intentional regenerate with: go test ./converters/hdf-to-cklb/go/ -update")
}
