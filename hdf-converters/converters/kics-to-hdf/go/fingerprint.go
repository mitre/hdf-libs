package kics

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "kics-to-hdf",
		Label:       "KICS",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			return fingerprintObject(obj)
		},
		DetectVersion: func(input any) string {
			obj, ok := input.(map[string]any)
			if !ok {
				return ""
			}
			v, _ := obj["kics_version"].(string)
			return v
		},
	})
}

// fingerprintObject keys on container names unique to KICS rather than the
// generic results/version pair, which matches several other tools and bare
// arrays of HDF requirements.
func fingerprintObject(obj map[string]any) float64 {
	// Emitted by every scan, including one that found nothing.
	if _, ok := obj["queries"].([]any); !ok {
		return 0
	}
	if _, ok := obj["kics_version"].(string); !ok {
		return 0
	}

	// Strong signal: the severity histogram KICS always reports.
	if _, ok := obj["severity_counters"].(map[string]any); ok {
		return 1.0
	}
	return 0.8
}
