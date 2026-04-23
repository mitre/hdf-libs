package nessus

import (
	"github.com/mitre/hdf-libs/hdf-converters/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
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
			if hdfutil.ExtractXMLRootElement(s) == "NessusClientData_v2" {
				return 1.0
			}
			return 0
		},
		DetectVersion: func(input any) string {
			s, ok := input.(string)
			if !ok {
				return ""
			}
			if hdfutil.ExtractXMLRootElement(s) == "NessusClientData_v2" {
				return "2"
			}
			return ""
		},
	})
}
