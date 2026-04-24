package zap_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestZapFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "zap-to-hdf",
		Label:       "OWASP ZAP",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects site array with @version at confidence 0.95", Input: map[string]any{"site": []any{}, "@version": "2.14.0", "@generated": "2024-01-01"}, Confidence: 0.95},
			{Name: "detects site array without version at confidence 0.85", Input: map[string]any{"site": []any{}}, Confidence: 0.85},
			{Name: "does not match when @version is not a string", Input: map[string]any{"site": []any{}, "@version": float64(2)}, Confidence: 0.85},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
