package scoutsuite

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestScoutsuiteFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "scoutsuite-to-hdf",
		Label:       "ScoutSuite",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name:       "detects services object with last_run at confidence 1.0",
				Input:      map[string]any{"services": map[string]any{"ec2": map[string]any{}}, "last_run": map[string]any{"time": "2024-01-01"}},
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match services without last_run", Input: map[string]any{"services": map[string]any{}}},
			{Name: "does not match services as array", Input: map[string]any{"services": []any{"ec2"}, "last_run": map[string]any{}}},
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
