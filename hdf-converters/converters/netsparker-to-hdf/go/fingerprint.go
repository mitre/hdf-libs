package netsparker

import (
	"github.com/mitre/hdf-converters/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "netsparker-to-hdf",
		Label:       "Netsparker",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			root := hdfutil.ExtractXMLRootElement(s)
			if root == "netsparker-enterprise" || root == "invicti-enterprise" {
				return 1.0
			}
			return 0
		},
	})
}
