package trufflehog

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestTrufflehogFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "trufflehog-to-hdf",
		Label:       "TruffleHog",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects single finding with DetectorName and SourceMetadata at confidence 1.0", Input: map[string]any{"DetectorName": "AWS", "SourceMetadata": map[string]any{"file": "secrets.txt"}}, Confidence: 1.0},
			{Name: "detects array of findings at confidence 1.0", Input: []any{map[string]any{"DetectorName": "AWS", "SourceMetadata": map[string]any{"file": "secrets.txt"}}}, Confidence: 1.0},
			{Name: "detects Raw and Verified at confidence 0.7", Input: map[string]any{"Raw": "AKIAIOSFODNN7EXAMPLE", "Verified": true}, Confidence: 0.7},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match empty array", Input: []any{}},
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
