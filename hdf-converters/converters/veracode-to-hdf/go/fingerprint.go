package veracode

import (
	"strings"

	"github.com/mitre/hdf-converters/registry"
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
			// Match <detailedreport or <ns:detailedreport with optional namespace prefix
			if strings.Contains(s, "detailedreport") && (strings.Contains(s, "<detailedreport") || strings.Contains(s, ":detailedreport")) {
				return 1.0
			}
			return 0
		},
	})
}
