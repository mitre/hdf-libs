package legacyhdf

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestLegacyHdfFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "legacyhdf-to-hdf",
		Label:       "Legacy InSpec exec-json",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name:       "detects legacy InSpec structure at confidence 1.0",
				Input:      map[string]any{"version": "1.0.0", "profiles": []any{map[string]any{"name": "profile1"}}, "platform": map[string]any{"name": "ubuntu", "release": "20.04"}},
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match when baselines array is present (current HDF)", Input: map[string]any{"version": "2.0.0", "profiles": []any{}, "platform": map[string]any{"name": "ubuntu"}, "baselines": []any{}}},
			{Name: "does not match when version is not a string", Input: map[string]any{"version": float64(1), "profiles": []any{}, "platform": map[string]any{"name": "ubuntu"}}},
			{Name: "does not match when profiles is not an array", Input: map[string]any{"version": "1.0.0", "profiles": "not-an-array", "platform": map[string]any{"name": "ubuntu"}}},
			{Name: "does not match when platform is not an object", Input: map[string]any{"version": "1.0.0", "profiles": []any{}, "platform": "not-an-object"}},
		},
	})
}
