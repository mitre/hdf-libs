package sarif

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestSarifFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "sarif-to-hdf",
		Label:       "SARIF",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects SARIF JSON at confidence 0.9", Input: map[string]any{"version": "2.1.0", "runs": []any{}}, Confidence: 0.9},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match GoSec JSON", Input: map[string]any{"GosecVersion": "2.18.2", "Issues": []any{}, "Stats": map[string]any{"files": float64(1)}}},
			{Name: "does not match when version is number", Input: map[string]any{"version": float64(2), "runs": []any{}}},
			{Name: "does not match when runs is object", Input: map[string]any{"version": "2.1.0", "runs": map[string]any{}}},
		},
	})
}
