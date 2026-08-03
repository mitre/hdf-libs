package hipcheck

import "github.com/mitre/hdf-libs/hdf-converters/v3/registry"

// isHipcheckReport scores how strongly a JSON object looks like a Hipcheck report.
func isHipcheckReport(obj map[string]any) float64 {
	_, hasVersion := obj["hipcheck_version"]
	rec, hasRec := obj["recommendation"]
	if hasVersion && hasRec {
		if recMap, ok := rec.(map[string]any); ok {
			if _, hasScore := recMap["risk_score"]; hasScore {
				return 1.0
			}
		}
		return 0.9
	}
	// hipcheck_version is distinctive on its own.
	if hasVersion {
		return 0.6
	}
	return 0
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "hipcheck-to-hdf",
		Label:       "Hipcheck",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			return isHipcheckReport(obj)
		},
	})
}
