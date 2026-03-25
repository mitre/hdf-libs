package conveyor

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestConveyorFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "conveyor-to-hdf",
		Label:       "Conveyor",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects api_response with results at confidence 1.0", Input: map[string]any{"api_response": map[string]any{"results": map[string]any{}}}, Confidence: 1.0},
			{Name: "detects api_response without results at confidence 0.6", Input: map[string]any{"api_response": map[string]any{}}, Confidence: 0.6},
			{Name: "detects api_server_version at confidence 0.5", Input: map[string]any{"api_server_version": "1.2.3"}, Confidence: 0.5},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
