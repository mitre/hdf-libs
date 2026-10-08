package hdftohtml

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func TestHdfToHtmlFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "hdf-to-html",
		Label:       "HDF to HTML",
		Direction:   registry.DirectionExport,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputRaw,
		Positive: []fptest.DetectionCase{
			{Name: "detects HDF JSON with baselines at confidence 0.5", Input: map[string]any{"baselines": []any{map[string]any{"name": "profile1"}}}, Confidence: 0.5},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match when baselines is not an array", Input: map[string]any{"baselines": "not-an-array"}},
			{Name: "does not match JSON without baselines", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
			{Name: "does not match a top-level array", Input: []any{}},
		},
	})
}
