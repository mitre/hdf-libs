package msftsecurescore

import "github.com/mitre/hdf-libs/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "msft-secure-score-to-hdf",
		Label:       "Microsoft Secure Score",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			ss, hasSS := obj["secureScore"]
			if !hasSS {
				return 0
			}
			ssMap, isSSMap := ss.(map[string]any)
			if !isSSMap {
				return 0
			}
			prof, hasProf := obj["profiles"]
			if !hasProf {
				return 0
			}
			profMap, isProfMap := prof.(map[string]any)
			if !isProfMap {
				return 0
			}
			ssValue, hasSSValue := ssMap["value"]
			if !hasSSValue {
				return 0
			}
			ssArr, isSSArr := ssValue.([]any)
			if !isSSArr {
				return 0
			}
			profValue, hasProfValue := profMap["value"]
			if !hasProfValue {
				return 0
			}
			if _, isProfArr := profValue.([]any); !isProfArr {
				return 0
			}
			// Check for controlScores in the first secureScore entry
			if len(ssArr) > 0 {
				if first, isMap := ssArr[0].(map[string]any); isMap {
					if cs, hasCS := first["controlScores"]; hasCS {
						if _, isCSArr := cs.([]any); isCSArr {
							return 1.0
						}
					}
				}
			}
			return 0.8
		},
	})
}
