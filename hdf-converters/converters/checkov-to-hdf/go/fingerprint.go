package checkov

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "checkov-to-hdf",
		Label:       "Checkov",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			// Checkov output can be a single object or an array of objects.
			// Each object has check_type, results, and summary fields.
			switch v := input.(type) {
			case map[string]any:
				return fingerprintObject(v)
			case []any:
				if len(v) == 0 {
					return 0
				}
				obj, ok := v[0].(map[string]any)
				if !ok {
					return 0
				}
				return fingerprintObject(obj)
			default:
				return 0
			}
		},
	})
}

func fingerprintObject(obj map[string]any) float64 {
	// Must have check_type (string) and results (object)
	checkType, hasCheckType := obj["check_type"]
	if !hasCheckType {
		return 0
	}
	if _, isStr := checkType.(string); !isStr {
		return 0
	}

	results, hasResults := obj["results"]
	if !hasResults {
		return 0
	}
	resultsMap, isMap := results.(map[string]any)
	if !isMap {
		return 0
	}

	// Results must have passed_checks and failed_checks as arrays
	passed, hasPassed := resultsMap["passed_checks"]
	if !hasPassed {
		return 0
	}
	if _, isArr := passed.([]any); !isArr {
		return 0
	}
	failed, hasFailed := resultsMap["failed_checks"]
	if !hasFailed {
		return 0
	}
	if _, isArr := failed.([]any); !isArr {
		return 0
	}

	// Strong signal: summary with checkov_version
	if summary, hasSummary := obj["summary"]; hasSummary {
		if summaryMap, ok := summary.(map[string]any); ok {
			if _, hasVersion := summaryMap["checkov_version"]; hasVersion {
				return 1.0
			}
		}
	}

	// Medium signal: has check_type + results with check arrays but no version
	return 0.8
}
