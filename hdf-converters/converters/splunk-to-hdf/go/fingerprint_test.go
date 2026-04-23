package splunk

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	"github.com/mitre/hdf-libs/hdf-converters/registry/fptest"
)

func TestSplunkFingerprint(t *testing.T) {
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "splunk-to-hdf",
		Label:       "Splunk",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "detects Splunk events with meta.subtype and meta.guid at confidence 1.0", Input: []any{map[string]any{"meta": map[string]any{"subtype": "header", "guid": "abc-123"}}}, Confidence: 1.0},
		},
		Negative: []fptest.DetectionCase{
			{Name: "does not match array without meta", Input: []any{map[string]any{"data": "something"}}},
			{Name: "does not match empty array", Input: []any{}},
			{Name: "does not match map input", Input: map[string]any{"version": "2.1.0", "runs": []any{}}},
		},
	})
}
