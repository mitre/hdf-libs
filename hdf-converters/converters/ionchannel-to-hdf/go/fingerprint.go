package ionchannel

import "github.com/mitre/hdf-libs/hdf-converters/registry"

// isIonChannelAnalysis checks whether a JSON object looks like Ion Channel analysis output.
// Returns confidence based on how many fingerprint keys are present.
func isIonChannelAnalysis(obj map[string]any) float64 {
	keys := []string{"analysis_id", "team_id", "source", "trigger_hash"}
	matches := 0
	for _, key := range keys {
		if _, ok := obj[key]; ok {
			matches++
		}
	}
	if matches == 0 {
		return 0
	}
	// Also require scan_summaries to differentiate from other formats
	if _, hasSS := obj["scan_summaries"]; !hasSS {
		return 0
	}
	if matches >= 3 {
		return 1.0
	}
	return 0.5
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "ionchannel-to-hdf",
		Label:       "Ion Channel",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			return isIonChannelAnalysis(obj)
		},
	})
}
