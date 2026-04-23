package msftdefenderendpoint

import "github.com/mitre/hdf-libs/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "msft-defender-endpoint-to-hdf",
		Label:       "Microsoft Defender for Endpoint",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			value, exists := obj["value"]
			if !exists {
				return 0
			}
			arr, isArr := value.([]any)
			if !isArr {
				return 0
			}
			if len(arr) == 0 {
				return 0
			}
			first, isMap := arr[0].(map[string]any)
			if !isMap {
				return 0
			}
			// MDE alerts have severity + category + evidence array
			sev, hasSev := first["severity"]
			cat, hasCat := first["category"]
			ev, hasEv := first["evidence"]
			if !hasSev || !hasCat || !hasEv {
				return 0
			}
			if _, isStr := sev.(string); !isStr {
				return 0
			}
			if _, isStr := cat.(string); !isStr {
				return 0
			}
			if _, isEvArr := ev.([]any); !isEvArr {
				return 0
			}
			return 1.0
		},
	})
}
