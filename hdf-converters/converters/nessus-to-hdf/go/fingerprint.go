package nessus

import (
	"strings"

	"github.com/mitre/hdf-converters/registry"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "nessus-to-hdf",
		Label:       "Nessus",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if strings.Contains(s, "<NessusClientData_v2") {
				return 1.0
			}
			return 0
		},
	})
}
