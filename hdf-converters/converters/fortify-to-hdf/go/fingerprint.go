package fortify

import (
	"strings"

	"github.com/mitre/hdf-converters/registry"
	shared "github.com/mitre/hdf-converters/shared/go"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "fortify-to-hdf",
		Label:       "Fortify",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if shared.ExtractXMLRootElement(s) != "FVDL" {
				return 0
			}
			// Higher confidence with Fortify namespace
			if strings.Contains(s, "xmlns.fortify.com") {
				return 1.0
			}
			return 0.95
		},
	})
}
