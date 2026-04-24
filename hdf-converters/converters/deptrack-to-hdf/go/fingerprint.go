package deptrack

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "deptrack-to-hdf",
		Label:       "Dependency-Track",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			findings, exists := obj["findings"]
			if !exists {
				return 0
			}
			findingsArr, isArr := findings.([]any)
			if !isArr {
				return 0
			}
			// Strong signal: has project and meta (standard FPF shape)
			_, hasProject := obj["project"]
			_, hasMeta := obj["meta"]
			if hasProject && hasMeta {
				return 1.0
			}
			// Medium signal: findings with vulnerability sub-objects
			if len(findingsArr) > 0 {
				if first, isMap := findingsArr[0].(map[string]any); isMap {
					if vuln, hasVuln := first["vulnerability"]; hasVuln {
						if vulnMap, isVulnMap := vuln.(map[string]any); isVulnMap {
							if id, hasID := vulnMap["vulnId"]; hasID {
								if _, isStr := id.(string); isStr {
									return 0.9
								}
							}
						}
					}
				}
			}
			return 0.5
		},
	})
}
