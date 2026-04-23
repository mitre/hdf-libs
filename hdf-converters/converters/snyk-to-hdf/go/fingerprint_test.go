package snyk

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestSnykFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "snyk-to-hdf",
		Label:       "Snyk",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects single project with packageManager at confidence 1.0", Input: map[string]any{"vulnerabilities": []any{}, "packageManager": "npm"}, Confidence: 1.0},
			{Name: "detects multi-project array at confidence 1.0", Input: []any{map[string]any{"vulnerabilities": []any{}, "packageManager": "npm"}}, Confidence: 1.0},
			{Name: "detects vulnerabilities without packageManager at confidence 0.5", Input: map[string]any{"vulnerabilities": []any{}}, Confidence: 0.5},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match empty array", Input: []any{}},
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
