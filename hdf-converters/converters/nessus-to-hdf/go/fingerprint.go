package nessus

import (
	"github.com/mitre/hdf-converters/registry"
	shared "github.com/mitre/hdf-converters/shared/go"
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
			if shared.ExtractXMLRootElement(s) == "NessusClientData_v2" {
				return 1.0
			}
			return 0
		},
		DetectVersion: func(input any) string {
			s, ok := input.(string)
			if !ok {
				return ""
			}
			if shared.ExtractXMLRootElement(s) == "NessusClientData_v2" {
				return "2"
			}
			return ""
		},
	})
}
