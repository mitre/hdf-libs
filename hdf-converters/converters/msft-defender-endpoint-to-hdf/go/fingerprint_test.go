package msftdefenderendpoint

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestMsftDefenderEndpointFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "msft-defender-endpoint-to-hdf",
		Label:       "Microsoft Defender for Endpoint",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects MDE alerts at confidence 1.0",
				Input: map[string]any{
					"value": []any{
						map[string]any{
							"severity": "High",
							"category": "Malware",
							"evidence": []any{
								map[string]any{"entityType": "File"},
							},
						},
					},
				},
				Confidence: 1.0,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match value array without required fields", Input: map[string]any{"value": []any{map[string]any{"severity": "High"}}}},
			{Name: "does not match empty value array", Input: map[string]any{"value": []any{}}},
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
