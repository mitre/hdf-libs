package zap_to_hdf

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "zap-to-hdf",
		Label:       "OWASP ZAP",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			// ZAP JSON has a "site" array and optionally "@version", "@generated"
			if site, exists := obj["site"]; exists {
				if _, isArr := site.([]any); isArr {
					// Higher confidence if @version or @generated present as strings
					versionIsStr := false
					generatedIsStr := false
					if v, hasVersion := obj["@version"]; hasVersion {
						_, versionIsStr = v.(string)
					}
					if g, hasGenerated := obj["@generated"]; hasGenerated {
						_, generatedIsStr = g.(string)
					}
					if versionIsStr || generatedIsStr {
						return 0.95
					}
					return 0.85
				}
			}
			return 0
		},
	})
}
