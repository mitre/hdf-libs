package nikto_to_hdf

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "nikto-to-hdf",
		Label:       "Nikto",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			// Nikto JSON has a "vulnerabilities" array and optionally "host", "port"
			if vulns, exists := obj["vulnerabilities"]; exists {
				if _, isArr := vulns.([]any); isArr {
					// Higher confidence if host/port present (standard Nikto fields)
					_, hasHost := obj["host"]
					_, hasPort := obj["port"]
					if hasHost || hasPort {
						return 0.95
					}
					return 0.85
				}
			}
			return 0
		},
	})
}
