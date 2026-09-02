package semgrep

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "semgrep-to-hdf",
		Label:       "Semgrep",
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
			version, _ := obj["version"].(string)
			return version
		},
	})
}

// fingerprintObject keys on semgrep-specific container names rather than the
// generic results/errors/version triple, which also matches bare arrays of HDF
// requirements and several other tools' output.
func fingerprintObject(obj map[string]any) float64 {
	// Both containers are always emitted, including by a scan with no findings.
	results, isArr := obj["results"].([]any)
	if !isArr {
		return 0
	}
	if _, isArr := obj["errors"].([]any); !isArr {
		return 0
	}

	paths, isMap := obj["paths"].(map[string]any)
	if !isMap {
		return 0
	}
	if _, isArr := paths["scanned"].([]any); !isArr {
		return 0
	}

	// Strong signal: a finding carrying semgrep's own extra/metadata envelope.
	if len(results) > 0 {
		if first, ok := results[0].(map[string]any); ok {
			if _, hasCheckID := first["check_id"].(string); hasCheckID {
				if _, hasExtra := first["extra"].(map[string]any); hasExtra {
					return 1.0
				}
			}
		}
	}

	// Empty scan: no finding to corroborate, so lean on the engine marker.
	if _, ok := obj["engine_requested"].(string); ok {
		return 0.9
	}

	return 0.7
}
