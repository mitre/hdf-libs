package msftdefendercloud

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "msft-defender-cloud-to-hdf",
		Label:       "Microsoft Defender for Cloud",
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
				return 0.5
			}
			first, isMap := arr[0].(map[string]any)
			if !isMap {
				return 0
			}
			props, hasProps := first["properties"]
			if !hasProps {
				return 0
			}
			propsMap, isPropsMap := props.(map[string]any)
			if !isPropsMap {
				return 0
			}
			if dn, hasDn := propsMap["displayName"]; hasDn {
				if _, isStr := dn.(string); isStr {
					return 1.0
				}
			}
			return 0
		},
	})
}
