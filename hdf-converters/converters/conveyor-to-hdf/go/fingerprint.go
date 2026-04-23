package conveyor

import "github.com/mitre/hdf-libs/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "conveyor-to-hdf",
		Label:       "Conveyor",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			// Primary: api_response with results
			if apiResp, exists := obj["api_response"]; exists {
				if resp, isMap := apiResp.(map[string]any); isMap {
					if _, hasResults := resp["results"]; hasResults {
						return 1.0
					}
					// Has api_response but no results — still likely Conveyor
					return 0.6
				}
			}
			// Secondary: has api_server_version (Conveyor-specific field)
			if ver, exists := obj["api_server_version"]; exists {
				if _, isStr := ver.(string); isStr {
					return 0.5
				}
			}
			return 0
		},
	})
}
