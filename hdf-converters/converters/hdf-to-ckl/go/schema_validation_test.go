package hdftockl

import (
	"fmt"
	"testing"

	corpus "github.com/mitre/hdf-libs/hdf-converters/v3/internal/corpus"
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
// stated reason. zero-baselines is permanent; baseline-empty-requirements is a
// live defect and is pinned below so the exemption cannot outlive it.
var corpusExemptions = map[string]string{
	"zero-baselines":              "baselines has no minItems, so an assessment that evaluated nothing is legal HDF that a checklist cannot represent — this converter rejects it deliberately, matching hdf-to-oscal-sar",
	"baseline-empty-requirements": "DEFECT hdf-libs-5gri.11: the converter emits an <iSTIG> with no <VULN>, which its own ParseCKL rejects. Exempted so the rest of the corpus can run, and pinned by TestConvertHDFToCKL_EmptyRequirementsDefectStillReproduces so removing the defect fails the pin",
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

// The exemption above is for a live defect, not a permanent property, so it is
// pinned: this test fails the moment hdf-libs-5gri.11 is fixed, which forces the
// exemption to be removed with it rather than silently outliving the bug.
func TestConvertHDFToCKL_EmptyRequirementsDefectStillReproduces(t *testing.T) {
	_, exempted := corpusExemptions["baseline-empty-requirements"]
	require.True(t, exempted, "this pin only means something while the case is exempted")

	input := []byte(`{"baselines":[{"name":"b","requirements":[]}],` +
		`"generator":{"name":"x","version":"1"},"timestamp":"2020-01-01T00:00:00Z"}`)

	out, err := ConvertHDFToCKL(input)
	require.NoError(t, err, "hdf-libs-5gri.11 fixed? The converter now rejects empty requirements — "+
		"delete the baseline-empty-requirements exemption and this test")
	require.Error(t, cklRoundTripValidator{}.Validate(out),
		"hdf-libs-5gri.11 fixed? Output now re-imports cleanly — "+
			"delete the baseline-empty-requirements exemption and this test")
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
