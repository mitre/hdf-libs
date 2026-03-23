package junit

import (
	"github.com/mitre/hdf-converters/registry"
	shared "github.com/mitre/hdf-converters/shared/go"
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
			root := shared.ExtractXMLRootElement(s)
			if root == "testsuites" || root == "testsuite" {
				return 1.0
			}
			return 0
		},
	})
}
