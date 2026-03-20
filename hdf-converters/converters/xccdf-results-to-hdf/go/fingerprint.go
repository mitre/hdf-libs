package xccdf

import (
	"strings"

	"github.com/mitre/hdf-converters/registry"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "xccdf-results-to-hdf",
		Label:       "XCCDF/ARF",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			// XCCDF Benchmark or ARF asset-report-collection root element
			// Handle namespace prefixes (e.g., <xccdf:Benchmark>)
			if strings.Contains(s, "<Benchmark") || strings.Contains(s, ":Benchmark") {
				return 1.0
			}
			if strings.Contains(s, "<asset-report-collection") || strings.Contains(s, ":asset-report-collection") {
				return 1.0
			}
			return 0
		},
	})
}
