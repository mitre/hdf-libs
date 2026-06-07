package csafvex

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "csaf-vex-to-hdf",
		Label:       "CSAF VEX",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputAmendments,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			doc, ok := obj["document"].(map[string]any)
			if !ok {
				return 0
			}
			if cat, _ := doc["category"].(string); cat != "csaf_vex" {
				return 0
			}
			if _, hasVer := doc["csaf_version"]; !hasVer {
				return 0
			}
			return 1.0
		},
	})
}
