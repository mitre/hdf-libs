package twistlock

import "github.com/mitre/hdf-converters/registry"

func hasTwistlockMarkers(obj map[string]any) float64 {
	if _, has := obj["complianceDistribution"]; has {
		return 1.0
	}
	if _, has := obj["vulnerabilityDistribution"]; has {
		return 0.9
	}
	return 0
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "twistlock-to-hdf",
		Label:       "Twistlock",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			// Container scan with "results" wrapper
			if results, hasResults := obj["results"]; hasResults {
				if resultsArr, isArr := results.([]any); isArr && len(resultsArr) > 0 {
					if first, isMap := resultsArr[0].(map[string]any); isMap {
						return hasTwistlockMarkers(first)
					}
				}
			}
			// Code repo scan — single result object without wrapper
			return hasTwistlockMarkers(obj)
		},
	})
}
