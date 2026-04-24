package jfrogxray

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestJfrogXrayFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "jfrog-xray-to-hdf",
		Label:       "JFrog Xray",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects data array with total_count at confidence 1.0", Input: map[string]any{"data": []any{}, "total_count": float64(42)}, Confidence: 1.0},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match data array without total_count", Input: map[string]any{"data": []any{}}},
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
