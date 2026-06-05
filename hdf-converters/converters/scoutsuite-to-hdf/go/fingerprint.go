package scoutsuite

import (
	"regexp"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
)

var scoutsuiteJSPrefixSniff = regexp.MustCompile(`(?i)^\s*scoutsuite_results\s*=\s*\{`)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "scoutsuite-to-hdf",
		Label:       "ScoutSuite",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			services, hasSvc := obj["services"]
			if !hasSvc {
				return 0
			}
			if _, isMap := services.(map[string]any); !isMap {
				return 0
			}
			lastRun, hasLR := obj["last_run"]
			if !hasLR {
				return 0
			}
			if _, isMap := lastRun.(map[string]any); !isMap {
				return 0
			}
			return 1.0
		},
	})

	registry.Register(registry.ConverterFingerprint{
		ID:          "scoutsuite-to-hdf-js",
		Label:       "ScoutSuite",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyText,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if scoutsuiteJSPrefixSniff.MatchString(s) {
				return 1.0
			}
			return 0
		},
	})
}
