package hdftooscalsar

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestHdfToOscalSarFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "hdf-to-oscal-sar",
		Label:       "HDF to OSCAL SAR",
		Direction:   registry.DirectionExport,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputRaw,
		Positive: []fptest.DetectionCase{
			{Name: "detects HDF v2 JSON with baselines at confidence 0.5", Input: map[string]any{"baselines": []any{map[string]any{"name": "profile1"}}}, Confidence: 0.5},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match when baselines is not an array", Input: map[string]any{"baselines": "not-an-array"}},
			{Name: "does not match JSON without baselines", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
