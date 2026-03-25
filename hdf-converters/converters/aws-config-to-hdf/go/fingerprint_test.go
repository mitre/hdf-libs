package awsconfig

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestAwsConfigFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "aws-config-to-hdf",
		Label:       "AWS Config",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects ConfigRules array at confidence 1.0", Input: map[string]any{"ConfigRules": []any{}}, Confidence: 1.0},
			{Name: "detects individual ConfigRuleName at confidence 0.7", Input: map[string]any{"ConfigRuleName": "s3-bucket-public-read-prohibited"}, Confidence: 0.7},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
