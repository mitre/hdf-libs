package burpsuite

import (
	"strings"

	"github.com/mitre/hdf-converters/registry"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "burpsuite-to-hdf",
		Label:       "Burp Suite",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			// BurpSuite XML has burpVersion attribute + <issues element
			if strings.Contains(s, "burpVersion") && strings.Contains(s, "<issues") {
				return 1.0
			}
			// Fallback: <issues> root without burpVersion (less certain)
			if strings.Contains(s, "<issues>") || strings.Contains(s, "<issues ") {
				return 0.7
			}
			return 0
		},
	})
}
