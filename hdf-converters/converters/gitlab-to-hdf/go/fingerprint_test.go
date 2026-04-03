package gitlab_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestGitlabFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "gitlab-to-hdf",
		Label:       "GitLab",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects vulnerabilities with scan.type at confidence 0.9", Input: map[string]any{"vulnerabilities": []any{}, "scan": map[string]any{"type": "sast"}}, Confidence: 0.9},
			{Name: "detects vulnerabilities with scan but no type at confidence 0.7", Input: map[string]any{"vulnerabilities": []any{}, "scan": map[string]any{}}, Confidence: 0.7},
			{Name: "detects bare vulnerabilities array at confidence 0.5", Input: map[string]any{"vulnerabilities": []any{}}, Confidence: 0.5},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
