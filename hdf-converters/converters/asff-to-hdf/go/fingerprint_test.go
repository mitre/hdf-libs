package asff

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestAsffFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "asff-to-hdf",
		Label:       "AWS Security Finding Format",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects Findings envelope with a ProductArn/GeneratorId finding", Input: map[string]any{"Findings": []any{map[string]any{"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub", "GeneratorId": "rule/1.1"}}}, Confidence: 0.95},
			{Name: "detects a bare array of findings", Input: []any{map[string]any{"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", "Types": []any{"TTPs"}}}, Confidence: 0.95},
			{Name: "detects a single finding object", Input: map[string]any{"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub", "Resources": []any{}}, Confidence: 0.95},
			{Name: "detects ProductArn alone at lower confidence", Input: map[string]any{"ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub"}, Confidence: 0.8},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match empty Findings envelope", Input: map[string]any{"Findings": []any{}}},
			{Name: "does not match empty array", Input: []any{}},
			{Name: "does not match a finding without ProductArn", Input: map[string]any{"Id": "x", "Title": "y"}},
			{Name: "does not match SARIF", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
