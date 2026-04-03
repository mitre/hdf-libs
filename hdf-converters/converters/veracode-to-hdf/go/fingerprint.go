package veracode

import (
	"github.com/mitre/hdf-converters/registry"
	shared "github.com/mitre/hdf-converters/shared/go"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "veracode-to-hdf",
		Label:       "Veracode",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if shared.ExtractXMLRootElement(s) == "detailedreport" {
				return 1.0
			}
			return 0
		},
	})
}
