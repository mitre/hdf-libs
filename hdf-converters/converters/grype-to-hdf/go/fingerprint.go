package grype_to_hdf

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "grype-to-hdf",
		Label:       "Grype",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			matches, hasMatches := obj["matches"]
			if !hasMatches {
				// Medium signal: descriptor.name === 'grype' without matches
				if desc, hasDesc := obj["descriptor"]; hasDesc {
					if descMap, isMap := desc.(map[string]any); isMap {
						if name, hasName := descMap["name"]; hasName {
							if s, isStr := name.(string); isStr && s == "grype" {
								return 0.8
							}
						}
					}
				}
				return 0
			}
			if _, isArr := matches.([]any); !isArr {
				return 0
			}
			// Strong signal: matches array with source object (standard Grype output)
			if src, hasSrc := obj["source"]; hasSrc {
				if _, isMap := src.(map[string]any); isMap {
					return 1.0
				}
			}
			// Medium signal: descriptor.name === 'grype'
			if desc, hasDesc := obj["descriptor"]; hasDesc {
				if descMap, isMap := desc.(map[string]any); isMap {
					if name, hasName := descMap["name"]; hasName {
						if s, isStr := name.(string); isStr && s == "grype" {
							return 0.8
						}
					}
				}
			}
			// Weak signal: matches array alone (could be other tools)
			return 0.4
		},
	})
}
