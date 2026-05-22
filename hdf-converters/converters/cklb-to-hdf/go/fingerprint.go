package cklb

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "cklb-to-hdf",
		Label:       "CKLB (DISA STIG Viewer 3.x JSON)",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if _, hasVersion := obj["cklb_version"]; !hasVersion {
				return 0
			}
			if _, isArr := obj["stigs"].([]any); !isArr {
				return 0
			}
			return 1.0
		},
	})
}
