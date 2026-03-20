package netsparker

import (
	"strings"

	"github.com/mitre/hdf-converters/registry"
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
			if strings.Contains(s, "<netsparker-enterprise") || strings.Contains(s, "<invicti-enterprise") {
				return 1.0
			}
			return 0
		},
	})
}
