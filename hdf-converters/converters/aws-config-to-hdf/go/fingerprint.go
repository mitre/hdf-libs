package awsconfig

import "github.com/mitre/hdf-libs/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "aws-config-to-hdf",
		Label:       "AWS Config",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			// Primary: ConfigRules array (the standard export shape)
			if rules, exists := obj["ConfigRules"]; exists {
				if _, isArr := rules.([]any); isArr {
					return 1.0
				}
			}
			// Secondary: individual config rule object with ConfigRuleName
			if name, exists := obj["ConfigRuleName"]; exists {
				if _, isStr := name.(string); isStr {
					return 0.7
				}
			}
			return 0
		},
	})
}
