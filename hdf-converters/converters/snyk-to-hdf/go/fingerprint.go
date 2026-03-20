package snyk

import "github.com/mitre/hdf-converters/registry"

func isSnykReport(obj map[string]any) float64 {
	vulns, hasVulns := obj["vulnerabilities"]
	if !hasVulns {
		return 0
	}
	if _, isArr := vulns.([]any); !isArr {
		return 0
	}
	if pm, hasPM := obj["packageManager"]; hasPM {
		if _, isStr := pm.(string); isStr {
			return 1.0
		}
	}
	return 0.5
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "snyk-to-hdf",
		Label:       "Snyk",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			// Handle array input (multi-project)
			if arr, isArr := input.([]any); isArr {
				if len(arr) == 0 {
					return 0
				}
				first, isMap := arr[0].(map[string]any)
				if !isMap {
					return 0
				}
				return isSnykReport(first)
			}
			// Single project
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			return isSnykReport(obj)
		},
	})
}
