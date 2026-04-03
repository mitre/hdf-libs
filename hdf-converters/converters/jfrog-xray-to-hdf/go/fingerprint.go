package jfrogxray

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "jfrog-xray-to-hdf",
		Label:       "JFrog Xray",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			data, hasData := obj["data"]
			if !hasData {
				return 0
			}
			if _, isArr := data.([]any); !isArr {
				return 0
			}
			if tc, hasTc := obj["total_count"]; hasTc {
				if _, isNum := tc.(float64); isNum {
					return 1.0
				}
			}
			return 0
		},
	})
}
