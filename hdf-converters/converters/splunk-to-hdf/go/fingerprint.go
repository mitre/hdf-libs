package splunk

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "splunk-to-hdf",
		Label:       "Splunk",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			// Splunk input is an array of event objects
			arr, isArr := input.([]any)
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
			meta, hasMeta := first["meta"]
			if !hasMeta {
				return 0
			}
			metaMap, isMetaMap := meta.(map[string]any)
			if !isMetaMap {
				return 0
			}
			subtype, hasSub := metaMap["subtype"]
			guid, hasGuid := metaMap["guid"]
			if !hasSub || !hasGuid {
				return 0
			}
			_, subIsStr := subtype.(string)
			_, guidIsStr := guid.(string)
			if subIsStr && guidIsStr {
				return 1.0
			}
			return 0
		},
	})
}
