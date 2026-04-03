package gosec

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "gosec-to-hdf",
		Label:       "GoSec",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			_, hasIssues := obj["Issues"]
			if !hasIssues {
				return 0
			}
			if _, isArr := obj["Issues"].([]any); !isArr {
				return 0
			}
			// Strong signal: GosecVersion present with Issues array
			if ver, hasVer := obj["GosecVersion"]; hasVer {
				if _, isStr := ver.(string); isStr {
					return 1.0
				}
			}
			// Medium signal: Issues array with Stats object (gosec shape without version)
			if stats, hasStats := obj["Stats"]; hasStats {
				if _, isMap := stats.(map[string]any); isMap {
					return 0.6
				}
			}
			return 0
		},
	})
}
