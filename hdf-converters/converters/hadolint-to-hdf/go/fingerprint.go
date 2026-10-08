package hadolint

import (
	"regexp"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
)

// hadolint keys every finding by its rule code: DL for its own rules, SC for
// the shellcheck rules it surfaces.
var ruleCodePattern = regexp.MustCompile(`^(DL|SC)\d+$`)

var hadolintLevels = map[string]bool{
	"error": true, "warning": true, "info": true, "style": true, "": true,
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "hadolint-to-hdf",
		Label:       "hadolint",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			// hadolint emits a bare array of findings. An empty array is a
			// clean run and indistinguishable from any other empty array, so
			// it scores nothing rather than claiming the input.
			findings, ok := input.([]any)
			if !ok || len(findings) == 0 {
				return 0
			}
			obj, ok := findings[0].(map[string]any)
			if !ok {
				return 0
			}
			return fingerprintFinding(obj)
		},
	})
}

func fingerprintFinding(obj map[string]any) float64 {
	code, ok := obj["code"].(string)
	if !ok {
		return 0
	}
	for _, field := range []string{"file", "message"} {
		if _, isStr := obj[field].(string); !isStr {
			return 0
		}
	}
	if _, isNum := obj["line"].(float64); !isNum {
		return 0
	}
	level, hasLevel := obj["level"].(string)
	if !hasLevel || !hadolintLevels[level] {
		return 0
	}
	// A rule code in hadolint's own namespace is the distinguishing signal;
	// the field shape alone could belong to another line-oriented linter.
	if ruleCodePattern.MatchString(code) {
		return 1.0
	}
	return 0.6
}
