package cyclonedx_to_hdf

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "cyclonedx-to-hdf",
		Label:       "CycloneDX",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if fmt, exists := obj["bomFormat"]; exists {
				if s, isStr := fmt.(string); isStr && s == "CycloneDX" {
					// Defer to cyclonedx-vex-to-hdf when the BOM carries
					// VEX analysis statements — the amendment-output target
					// is more specific than the SBOM-as-results mapping.
					if vulns, ok := obj["vulnerabilities"].([]any); ok {
						for _, v := range vulns {
							vm, ok := v.(map[string]any)
							if !ok {
								continue
							}
							if _, has := vm["analysis"]; has {
								return 0.8
							}
						}
					}
					return 1.0
				}
			}
			return 0
		},
		DetectVersion: func(input any) string {
			obj, ok := input.(map[string]any)
			if !ok {
				return ""
			}
			if v, ok := obj["specVersion"].(string); ok {
				return v
			}
			return ""
		},
	})
}
