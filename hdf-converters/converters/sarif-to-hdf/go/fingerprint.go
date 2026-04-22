package sarif

import "github.com/mitre/hdf-libs/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "sarif-to-hdf",
		Label:       "SARIF",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			ver, hasVer := obj["version"]
			if !hasVer {
				return 0
			}
			if _, isStr := ver.(string); !isStr {
				return 0
			}
			runs, hasRuns := obj["runs"]
			if !hasRuns {
				return 0
			}
			if _, isArr := runs.([]any); !isArr {
				return 0
			}
			return 0.9
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
