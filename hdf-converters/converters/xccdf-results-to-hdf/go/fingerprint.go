package xccdf

import (
	"github.com/mitre/hdf-converters/registry"
	shared "github.com/mitre/hdf-converters/shared/go"
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
			// XCCDF Benchmark or ARF asset-report-collection root element.
			// ExtractXMLRootElement strips namespace prefixes automatically.
			root := shared.ExtractXMLRootElement(s)
			if root == "Benchmark" || root == "asset-report-collection" {
				return 1.0
			}
			return 0
		},
	})
}
