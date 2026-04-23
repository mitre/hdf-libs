package hdfv2passthrough

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestHdfV2PassthroughFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "hdf-v2-passthrough",
		Label:       "HDF v2",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects HDF v2 JSON with baselines array at confidence 0.8", Input: map[string]any{"baselines": []any{map[string]any{"name": "profile1"}}}, Confidence: 0.8},
			{Name: "detects HDF v2 with empty baselines array at confidence 0.8", Input: map[string]any{"baselines": []any{}}, Confidence: 0.8},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match when baselines is not an array", Input: map[string]any{"baselines": "not-an-array"}},
			{Name: "does not match JSON without baselines", Input: map[string]any{"version": "2.1.0", "profiles": []any{}}},
		},
	})
}
