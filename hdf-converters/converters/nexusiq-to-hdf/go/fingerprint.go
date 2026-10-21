package nexusiq

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "nexusiq-to-hdf",
		Label:       "Nexus IQ",
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
	})
}

// fingerprintObject keys on the envelope every IQ CLI result carries, including
// one with no violations; an alert's policyViolationId confirms it.
func fingerprintObject(obj map[string]any) float64 {
	if _, ok := obj["applicationId"].(string); !ok {
		return 0
	}
	if _, ok := obj["scanId"].(string); !ok {
		return 0
	}
	result, ok := obj["policyEvaluationResult"].(map[string]any)
	if !ok {
		return 0
	}
	if alerts, ok := result["alerts"].([]any); ok && len(alerts) > 0 {
		if alert, ok := alerts[0].(map[string]any); ok {
			if trigger, ok := alert["trigger"].(map[string]any); ok {
				if _, ok := trigger["policyViolationId"].(string); ok {
					return 1.0
				}
			}
		}
	}
	return 0.9
}
