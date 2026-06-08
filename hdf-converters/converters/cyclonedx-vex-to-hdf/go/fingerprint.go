package cyclonedxvex

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "cyclonedx-vex-to-hdf",
		Label:       "CycloneDX VEX",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputAmendments,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if fmt, _ := obj["bomFormat"].(string); fmt != "CycloneDX" {
				return 0
			}
			vulns, ok := obj["vulnerabilities"].([]any)
			if !ok || len(vulns) == 0 {
				return 0
			}
			// Distinguish a VEX-bearing BOM (vulnerabilities[].analysis is
			// present) from a plain SBOM that happens to list vulnerabilities
			// without analysis. The plain SBOM case is handled by the
			// existing cyclonedx-to-hdf converter.
			for _, v := range vulns {
				vm, ok := v.(map[string]any)
				if !ok {
					continue
				}
				if _, has := vm["analysis"]; has {
					return 1.0
				}
			}
			return 0
		},
	})
}
