package nikto_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/mitre/hdf-converters/registry/fptest"
)

func TestNiktoFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "nikto-to-hdf",
		Label:       "Nikto",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects vulnerabilities with host at confidence 0.95", Input: map[string]any{"vulnerabilities": []any{}, "host": "example.com", "port": "443"}, Confidence: 0.95},
			{Name: "detects vulnerabilities without host/port at confidence 0.85", Input: map[string]any{"vulnerabilities": []any{}}, Confidence: 0.85},
			{Name: "does not match when host/port are not strings", Input: map[string]any{"vulnerabilities": []any{}, "host": float64(123), "port": float64(443)}, Confidence: 0.85},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
