package sonarqube

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "sonarqube-to-hdf",
		Label:       "SonarQube",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			issues, hasIssues := obj["issues"]
			if !hasIssues {
				return 0
			}
			issuesArr, isArr := issues.([]any)
			if !isArr {
				return 0
			}
			if len(issuesArr) == 0 {
				return 0.5
			}
			first, isMap := issuesArr[0].(map[string]any)
			if !isMap {
				return 0
			}
			rule, hasRule := first["rule"]
			comp, hasComp := first["component"]
			if hasRule && hasComp {
				_, ruleIsStr := rule.(string)
				_, compIsStr := comp.(string)
				if ruleIsStr && compIsStr {
					return 1.0
				}
			}
			return 0
		},
	})
}
