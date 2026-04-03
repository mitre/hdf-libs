package hdftooscalsar

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "hdf-to-oscal-sar",
		Label:       "HDF to OSCAL SAR",
		Direction:   registry.DirectionExport,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputRaw,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if baselines, exists := obj["baselines"]; exists {
				if _, isArr := baselines.([]any); isArr {
					return 0.5
				}
			}
			return 0
		},
	})
}
