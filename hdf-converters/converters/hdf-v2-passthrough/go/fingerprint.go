package hdfv2passthrough

import "github.com/mitre/hdf-libs/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "hdf-v2-passthrough",
		Label:       "HDF v2",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if baselines, exists := obj["baselines"]; exists {
				if _, isArr := baselines.([]any); isArr {
					return 0.8
				}
			}
			return 0
		},
	})
}
