package cklb

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestCKLBFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "cklb-to-hdf",
		Label:       "CKLB (DISA STIG Viewer 3.x JSON)",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects cklb_version + stigs array at confidence 1.0", Input: map[string]any{"cklb_version": "1.0", "stigs": []any{}}, Confidence: 1.0},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match without cklb_version", Input: map[string]any{"stigs": []any{}}},
			{Name: "does not match when stigs is not an array", Input: map[string]any{"cklb_version": "1.0", "stigs": "nope"}},
			{Name: "does not match an array input", Input: []any{}},
			{Name: "does not match a different format", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
