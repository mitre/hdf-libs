package msftdefendercloud

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestMsftDefenderCloudFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "msft-defender-cloud-to-hdf",
		Label:       "Microsoft Defender for Cloud",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name:       "detects value array with properties.displayName at confidence 1.0",
				Input:      map[string]any{"value": []any{map[string]any{"properties": map[string]any{"displayName": "Enable MFA"}}}},
				Confidence: 1.0,
			},
			{
				Name:       "detects empty value array at confidence 0.5",
				Input:      map[string]any{"value": []any{}},
				Confidence: 0.5,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
