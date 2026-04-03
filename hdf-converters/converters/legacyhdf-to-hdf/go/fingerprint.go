package legacyhdf

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "legacyhdf-to-hdf",
		Label:       "HDF v1 (Legacy)",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			// Must NOT have baselines[] (that would be HDF v2)
			if baselines, exists := obj["baselines"]; exists {
				if _, isArr := baselines.([]any); isArr {
					return 0
				}
			}
			// V1 structure: profiles[] + platform object + version string
			_, hasVersion := obj["version"].(string)
			profiles, hasProfiles := obj["profiles"]
			platform, hasPlatform := obj["platform"]
			if hasVersion && hasProfiles && hasPlatform {
				if _, isArr := profiles.([]any); isArr {
					if _, isMap := platform.(map[string]any); isMap {
						return 1.0
					}
				}
			}
			return 0
		},
		DetectVersion: func(input any) string {
			obj, ok := input.(map[string]any)
			if !ok {
				return ""
			}
			if v, ok := obj["version"].(string); ok {
				return v
			}
			return ""
		},
	})
}
