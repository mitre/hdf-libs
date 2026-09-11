package hdftocklb

import (
	"fmt"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
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

// corpusExemptions mirrors hdf-to-ckl's: zero-baselines is a deliberate,
// permanent rejection; baseline-empty-requirements is a live defect, pinned
// below so the exemption cannot outlive it.
var corpusExemptions = map[string]string{
	"zero-baselines":              "baselines has no minItems, so an assessment that evaluated nothing is legal HDF a checklist cannot represent — rejected deliberately, matching hdf-to-ckl and hdf-to-oscal-sar",
	"baseline-empty-requirements": "DEFECT, tracked on the exporter-conformance board: an empty requirements list yields \"rules\": null rather than an empty array. Exempted so the rest of the corpus can run, and pinned by TestConvertHDFToCKLB_RulesNullDefectStillReproduces",
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

// The exemption above is for a live defect, not a permanent property, so it is
// pinned: this fails the moment the defect is fixed, forcing the exemption
// to be removed with it rather than silently outliving the bug.
func TestConvertHDFToCKLB_RulesNullDefectStillReproduces(t *testing.T) {
	_, exempted := corpusExemptions["baseline-empty-requirements"]
	require.True(t, exempted, "this pin only means something while the case is exempted")

	input := []byte(`{"baselines":[{"name":"b","requirements":[]}],` +
		`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`)

	out, err := ConvertHDFToCKLB(input)
	require.NoError(t, err, "Defect fixed? The converter now rejects empty requirements — "+
		"delete the baseline-empty-requirements exemption and this test")
	require.Contains(t, string(out), `"rules": null`,
		"Defect fixed? rules is no longer null — "+
			"delete the baseline-empty-requirements exemption and this test")
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
