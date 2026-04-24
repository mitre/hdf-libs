package cyclonedx_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestCyclonedxFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "cyclonedx-to-hdf",
		Label:       "CycloneDX",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects CycloneDX bomFormat at confidence 1.0", Input: map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []any{}}, Confidence: 1.0},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match wrong bomFormat value", Input: map[string]any{"bomFormat": "SPDX"}},
			{Name: "does not match different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
