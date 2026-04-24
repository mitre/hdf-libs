package neuvector

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestNeuvectorFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "neuvector-to-hdf",
		Label:       "NeuVector",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{
				Name:       "detects report.vulnerabilities with name and package_name at confidence 1.0",
				Input:      map[string]any{"report": map[string]any{"vulnerabilities": []any{map[string]any{"name": "CVE-2021-12345", "package_name": "openssl"}}}},
				Confidence: 1.0,
			},
			{
				Name:       "detects empty vulnerabilities at confidence 0.7",
				Input:      map[string]any{"report": map[string]any{"vulnerabilities": []any{}}},
				Confidence: 0.7,
			},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
