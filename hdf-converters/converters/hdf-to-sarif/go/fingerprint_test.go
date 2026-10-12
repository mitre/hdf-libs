package hdftosarif

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestHdfToSarifFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "hdf-to-sarif",
		Label:       "HDF to SARIF",
		Direction:   registry.DirectionExport,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputRaw,
		Positive: []fptest.DetectionCase{
			{
				Name:       "detects HDF results with baselines at confidence 0.5",
				Input:      map[string]any{"baselines": []any{map[string]any{"name": "profile1"}}},
				Confidence: 0.5,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match when baselines is not an array", Input: map[string]any{"baselines": "not-an-array"}},
			{Name: "does not match a SARIF log, which is this converter's OUTPUT", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
			{Name: "does not match a non-object", Input: []any{}},
		},
	})
}
