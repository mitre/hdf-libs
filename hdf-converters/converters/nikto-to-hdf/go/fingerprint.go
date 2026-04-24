package nikto_to_hdf

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

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
					// Higher confidence if host/port present as strings (standard Nikto fields)
					hostIsStr := false
					portIsStr := false
					if h, hasHost := obj["host"]; hasHost {
						_, hostIsStr = h.(string)
					}
					if p, hasPort := obj["port"]; hasPort {
						_, portIsStr = p.(string)
					}
					if hostIsStr || portIsStr {
						return 0.95
					}
					return 0.85
				}
			}
			return 0
		},
	})
}
