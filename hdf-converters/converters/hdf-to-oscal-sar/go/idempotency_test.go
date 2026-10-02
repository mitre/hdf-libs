package hdftooscalsar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	oscal "github.com/mitre/hdf-libs/hdf-converters/v3/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sarRoundTrip runs one OSCAL SAR -> HDF -> OSCAL SAR hop.
func sarRoundTrip(t *testing.T, oscalDoc []byte) []byte {
	t.Helper()
	hdfDoc, err := oscal.ConvertAssessmentResultsToHDF(oscalDoc, "test")
	require.NoError(t, err)
	hdfBytes, err := json.Marshal(hdfDoc)
	require.NoError(t, err)
	out, err := ConvertHDFToOSCALSAR(hdfBytes, "test")
	require.NoError(t, err)
	return out
}

// observationDescriptions returns every observation description in an exported
// SAR, in result/observation order, for a focused prose comparison.
func observationDescriptions(t *testing.T, sar []byte) []string {
	t.Helper()
	var doc oscalSARDocument
	require.NoError(t, json.Unmarshal(sar, &doc))
	var out []string
	for _, r := range doc.AssessmentResults.Results {
		for _, o := range r.Observations {
			out = append(out, o.Description)
		}
	}
	return out
}

// AC (ADR-0014 §3.5): the SAR round trip is idempotent on observation.description
// from the RAW third-party fixture. Before this card the first HDF-produced
// export derived each observation description from the source's methods, subjects
// and risk, while the second derived it from the exporter's own canonical
// emission, so o2 != o3 on the description alone. The exporter now synthesizes the
// description from the objects it emits, so the first export already equals the
// second.
func TestObservationDescriptionIdempotentFromRawSAR(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "oscal-to-hdf", "fixtures", "input", "sar-fedramp.json"))
	require.NoError(t, err)

	o2 := sarRoundTrip(t, raw)
	o3 := sarRoundTrip(t, o2)

	assert.Equal(t, observationDescriptions(t, o2), observationDescriptions(t, o3),
		"observation.description must not regenerate on the second export")

	m2, err := shared.MaskVolatileJSON(o2, sarVolatileKeys)
	require.NoError(t, err)
	m3, err := shared.MaskVolatileJSON(o3, sarVolatileKeys)
	require.NoError(t, err)
	assert.Equal(t, m2, m3, "the whole SAR converges from the raw fixture (export1 == export2)")
}
