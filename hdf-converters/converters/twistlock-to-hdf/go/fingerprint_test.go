package twistlock

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestTwistlockFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "twistlock-to-hdf",
		Label:       "Twistlock",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects results with complianceDistribution at confidence 1.0", Input: map[string]any{"results": []any{map[string]any{"complianceDistribution": map[string]any{"critical": float64(0)}}}}, Confidence: 1.0},
			{Name: "detects results with vulnerabilityDistribution at confidence 0.9", Input: map[string]any{"results": []any{map[string]any{"vulnerabilityDistribution": map[string]any{"critical": float64(0)}}}}, Confidence: 0.9},
			{Name: "detects single object with complianceDistribution at confidence 1.0", Input: map[string]any{"complianceDistribution": map[string]any{"critical": float64(0)}}, Confidence: 1.0},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
