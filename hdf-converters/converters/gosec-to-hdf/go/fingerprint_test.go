package gosec

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestGosecFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "gosec-to-hdf",
		Label:       "GoSec",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name:       "detects GosecVersion with Issues at confidence 1.0",
				Input:      map[string]any{"GosecVersion": "2.18.2", "Issues": []any{}, "Stats": map[string]any{"files": float64(1)}},
				Confidence: 1.0,
			},
			{
				Name:       "detects Issues with Stats but no version at confidence 0.6",
				Input:      map[string]any{"Issues": []any{}, "Stats": map[string]any{"files": float64(1)}},
				Confidence: 0.6,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match Issues alone without Stats or version", Input: map[string]any{"Issues": []any{}}},
			{Name: "does not match SARIF format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
