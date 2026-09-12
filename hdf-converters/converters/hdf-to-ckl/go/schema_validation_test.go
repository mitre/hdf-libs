package hdftockl

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

// NO PUBLISHED SCHEMA FOR .ckl. Searched 2026-09-09: DISA distributes STIG
// Viewer and documents the checklist format in the STIG Viewer user guide, but
// publishes no authoritative XSD — the same conclusion the vendored XCCDF chain
// records for CKL in ../../hdf-to-xccdf/schemas/provenance.txt. So the
// conformance check available here is a round trip: output this repo's own
// ParseCKL cannot read back is malformed in the way a schema would catch.
//
// This is a real check, not a stand-in that always passes: it is what catches an
// <iSTIG> carrying no <VULN>, which ParseCKL rejects.
type cklRoundTripValidator struct{}

func (cklRoundTripValidator) Validate(doc []byte) error {
	if len(doc) == 0 {
		// Not reachable from zero baselines -- the converter errors on those
		// rather than emitting nothing -- but an empty document is not a
		// parse failure, so it is not reported as one.
		return nil
	}
	cl, err := checklist.ParseCKL(doc)
	if err != nil {
		return fmt.Errorf("output does not re-import through ParseCKL: %w", err)
	}
	if cl == nil {
		return fmt.Errorf("ParseCKL returned no checklist for non-empty output")
	}
	return nil
}

// corpusExemptions are the cases this converter does not satisfy, each for a
// stated reason. Only zero-baselines remains, and it is permanent: a checklist
// cannot represent an assessment that evaluated nothing. It is pinned below.
var corpusExemptions = map[string]string{
	"zero-baselines": "baselines has no minItems, so an assessment that evaluated nothing is legal HDF that a checklist cannot represent — this converter rejects it deliberately, matching hdf-to-oscal-sar",
}

func corpusMinusExemptions(t *testing.T) []corpus.CorpusCase {
	t.Helper()
	all := corpus.ResultsCorpus()
	kept := make([]corpus.CorpusCase, 0, len(all))
	for _, c := range all {
		if reason, skipped := corpusExemptions[c.Name]; skipped {
			t.Logf("corpus case %q exempted — %s", c.Name, reason)
			continue
		}
		kept = append(kept, c)
	}
	require.NotEmpty(t, kept, "every case exempted — the run would prove nothing")
	return kept
}

// TestConvertHDFToCKL_AdversarialCorpus holds this converter to the shared
// corpus contracts, with the round trip standing in for the schema DISA does not
// publish.
func TestConvertHDFToCKL_AdversarialCorpus(t *testing.T) {
	corpus.RunSchemaCorpus(t, cklRoundTripValidator{}, corpusMinusExemptions(t), ConvertHDFToCKL)
}

// The zero-baselines exemption above claims a deliberate rejection. hdf-to-oscal-sar
// backs its identical exemption with a pin; without one here the exemption could
// silently become a real hole, so this asserts the rejection actually happens.
func TestConvertHDFToCKL_RejectsZeroBaselines(t *testing.T) {
	_, exempted := corpusExemptions["zero-baselines"]
	require.True(t, exempted, "this pin only means something while the case is exempted")

	_, err := ConvertHDFToCKL([]byte(`{"baselines":[],"generator":{"name":"x","version":"1"},` +
		`"timestamp":"2020-01-01T00:00:00Z"}`))
	require.Error(t, err, "zero baselines must be rejected, not converted into an empty checklist")
}

// corpusRejected marks a corpus case the converter refuses; the two languages
// must agree on rejection as well as on output.
const corpusRejected = "REJECTED"

// Pins what this converter emits for every corpus input so the two languages are
// compared against one another rather than each against its own expectations.
// Go owns regeneration (go test ./converters/hdf-to-ckl/go/ -update); TypeScript only
// verifies. This is what makes the byte-identical claim an assertion.
func TestConvertHDFToCKL_CorpusOutputGolden(t *testing.T) {
	outputs := make(map[string]string, len(corpus.ResultsCorpus()))
	for _, c := range corpus.ResultsCorpus() {
		out, err := corpus.ConvertNoPanic(ConvertHDFToCKL, c.Input)
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
		"corpus output changed; if intentional regenerate with: go test ./converters/hdf-to-ckl/go/ -update")
}
