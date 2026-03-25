package grype_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestGrypeFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "grype-to-hdf",
		Label:       "Grype",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects matches with source at confidence 1.0", Input: map[string]any{"matches": []any{}, "source": map[string]any{"type": "image"}}, Confidence: 1.0},
			{Name: "detects descriptor.name grype without matches at confidence 0.8", Input: map[string]any{"descriptor": map[string]any{"name": "grype"}}, Confidence: 0.8},
			{Name: "detects matches with descriptor.name grype at confidence 0.8", Input: map[string]any{"matches": []any{}, "descriptor": map[string]any{"name": "grype"}}, Confidence: 0.8},
			{Name: "detects bare matches array at confidence 0.4", Input: map[string]any{"matches": []any{}}, Confidence: 0.4},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
