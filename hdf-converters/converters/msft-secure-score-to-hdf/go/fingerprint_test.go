package msftsecurescore

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestMsftSecureScoreFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "msft-secure-score-to-hdf",
		Label:       "Microsoft Secure Score",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects full shape with controlScores at confidence 1.0",
				Input: map[string]any{
					"secureScore": map[string]any{
						"value": []any{
							map[string]any{
								"controlScores": []any{
									map[string]any{"controlName": "MFAEnabled"},
								},
							},
						},
					},
					"profiles": map[string]any{
						"value": []any{},
					},
				},
				Confidence: 1.0,
			},
			{
				Name: "detects shape without controlScores at confidence 0.8",
				Input: map[string]any{
					"secureScore": map[string]any{"value": []any{}},
					"profiles":    map[string]any{"value": []any{}},
				},
				Confidence: 0.8,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match without profiles", Input: map[string]any{"secureScore": map[string]any{"value": []any{}}}},
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
