package junit

import (
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "junit-to-hdf",
		Label:       "JUnit",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			root := hdfutil.ExtractXMLRootElement(s)
			if root == "testsuites" || root == "testsuite" {
				return 1.0
			}
			return 0
		},
	})
}
