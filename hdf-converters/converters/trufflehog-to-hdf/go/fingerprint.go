package trufflehog

import "github.com/mitre/hdf-libs/hdf-converters/registry"

func isTrufflehogFinding(obj map[string]any) float64 {
	detName, hasDetName := obj["DetectorName"]
	_, hasSrcMeta := obj["SourceMetadata"]
	if hasDetName && hasSrcMeta {
		if _, isStr := detName.(string); isStr {
			return 1.0
		}
	}
	raw, hasRaw := obj["Raw"]
	verified, hasVerified := obj["Verified"]
	if hasRaw && hasVerified {
		if _, isStr := raw.(string); isStr {
			if _, isBool := verified.(bool); isBool {
				return 0.7
			}
		}
	}
	return 0
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "trufflehog-to-hdf",
		Label:       "TruffleHog",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			// Array of findings
			if arr, isArr := input.([]any); isArr {
				if len(arr) == 0 {
					return 0
				}
				first, isMap := arr[0].(map[string]any)
				if !isMap {
					return 0
				}
				return isTrufflehogFinding(first)
			}
			// Single finding object
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			return isTrufflehogFinding(obj)
		},
	})
}
