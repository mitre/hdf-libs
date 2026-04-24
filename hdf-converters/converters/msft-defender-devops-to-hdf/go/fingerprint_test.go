package msftdefenderdevops

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestMsftDefenderDevopsFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "msft-defender-devops-to-hdf",
		Label:       "Microsoft Defender for DevOps",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name: "detects SARIF with MSDO tool driver at confidence 0.95",
				Input: map[string]any{
					"version": "2.1.0",
					"runs": []any{
						map[string]any{
							"tool": map[string]any{
								"driver": map[string]any{
									"name":         "Microsoft Security DevOps",
									"organization": "Microsoft",
								},
							},
						},
					},
				},
				Confidence: 0.95,
			},
		},
		Negative: []fptest.DetectionCase{
			{
				Name: "does not match plain SARIF without MSDO driver",
				Input: map[string]any{
					"version": "2.1.0",
					"runs": []any{
						map[string]any{
							"tool": map[string]any{
								"driver": map[string]any{
									"name": "eslint",
								},
							},
						},
					},
				},
			},
			{Name: "does not match different format", Input: map[string]any{"Issues": []any{}, "GosecVersion": "2.18.2"}},
		},
	})
}
