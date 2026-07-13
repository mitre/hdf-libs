package asff

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

// isASFFFinding scores how strongly an object looks like an ASFF finding.
// ProductArn is ASFF's distinctive marker; a second ASFF-shaped field raises
// confidence.
func isASFFFinding(obj map[string]any) float64 {
	arn, ok := obj["ProductArn"].(string)
	if !ok || arn == "" {
		return 0
	}
	_, hasGenID := obj["GeneratorId"]
	_, hasTypes := obj["Types"]
	_, hasResources := obj["Resources"]
	if hasGenID || hasTypes || hasResources {
		return 0.95
	}
	return 0.8
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "asff-to-hdf",
		Label:       "AWS Security Finding Format",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			switch v := input.(type) {
			case map[string]any:
				// { "Findings": [...] } envelope.
				if findings, ok := v["Findings"].([]any); ok {
					if len(findings) == 0 {
						return 0
					}
					first, ok := findings[0].(map[string]any)
					if !ok {
						return 0
					}
					return isASFFFinding(first)
				}
				// A single bare finding object.
				return isASFFFinding(v)
			case []any:
				// A bare array of findings.
				if len(v) == 0 {
					return 0
				}
				first, ok := v[0].(map[string]any)
				if !ok {
					return 0
				}
				return isASFFFinding(first)
			default:
				return 0
			}
		},
	})
}
