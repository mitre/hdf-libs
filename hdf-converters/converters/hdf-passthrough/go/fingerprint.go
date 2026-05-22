package hdfpassthrough

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

// FingerprintID is the detection ID for native (already-HDF) input — a document
// with a top-level baselines[] array that needs no conversion. The convert
// command normalizes this to the "hdf" source name when resolving an export
// converter.
const FingerprintID = "hdf-passthrough"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          FingerprintID,
		Label:       "HDF",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if baselines, exists := obj["baselines"]; exists {
				if _, isArr := baselines.([]any); isArr {
					return 0.8
				}
			}
			return 0
		},
	})
}
