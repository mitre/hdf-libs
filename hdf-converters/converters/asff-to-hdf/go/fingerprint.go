package asff

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "asff-to-hdf",
		Label:       "ASFF (AWS Security Finding Format)",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			findings, hasFindings := obj["Findings"].([]any)
			if !hasFindings || len(findings) == 0 {
				return 0
			}
			first, ok := findings[0].(map[string]any)
			if !ok {
				return 0
			}
			// Strongest signal: ASFF SchemaVersion + ProductArn shape.
			_, hasSchemaVersion := first["SchemaVersion"]
			productArn, hasProductArn := first["ProductArn"].(string)
			if hasSchemaVersion && hasProductArn && len(productArn) > 0 {
				return 1.0
			}
			if hasProductArn && len(productArn) > 0 {
				return 0.7
			}
			return 0
		},
	})
}
