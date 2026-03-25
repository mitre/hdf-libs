package deptrack

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestDeptrackFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "deptrack-to-hdf",
		Label:       "Dependency-Track",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name:       "detects full FPF shape at confidence 1.0",
				Input:      map[string]any{"findings": []any{}, "project": map[string]any{"name": "test"}, "meta": map[string]any{"totalCount": float64(0)}},
				Confidence: 1.0,
			},
			{
				Name:       "detects findings with vulnerability.vulnId at confidence 0.9",
				Input:      map[string]any{"findings": []any{map[string]any{"vulnerability": map[string]any{"vulnId": "CVE-2021-12345"}}}},
				Confidence: 0.9,
			},
			{
				Name:       "detects bare findings array at confidence 0.5",
				Input:      map[string]any{"findings": []any{}},
				Confidence: 0.5,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
