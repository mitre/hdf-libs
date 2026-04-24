package xccdf

import (
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
			root := hdfutil.ExtractXMLRootElement(s)
			if root == "Benchmark" || root == "asset-report-collection" {
				return 1.0
			}
			return 0
		},
	})
}
