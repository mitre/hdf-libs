package scoutsuite

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "scoutsuite-to-hdf",
		Label:       "ScoutSuite",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			services, hasSvc := obj["services"]
			if !hasSvc {
				return 0
			}
			// services must be an object (map), not an array
			if _, isMap := services.(map[string]any); !isMap {
				return 0
			}
			lastRun, hasLR := obj["last_run"]
			if !hasLR {
				return 0
			}
			if _, isMap := lastRun.(map[string]any); !isMap {
				return 0
			}
			return 1.0
		},
	})
}
