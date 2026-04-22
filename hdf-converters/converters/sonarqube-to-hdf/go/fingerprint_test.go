package sonarqube

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestSonarqubeFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "sonarqube-to-hdf",
		Label:       "SonarQube",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects issues with rule and component at confidence 1.0", Input: map[string]any{"issues": []any{map[string]any{"rule": "java:S1135", "component": "src/Main.java"}}}, Confidence: 1.0},
			{Name: "detects empty issues array at confidence 0.5", Input: map[string]any{"issues": []any{}}, Confidence: 0.5},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
