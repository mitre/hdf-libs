package msftdefenderdevops

import (
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
)

func isMsdoDriver(driver map[string]any) bool {
	for _, key := range []string{"name", "organization", "product", "fullName"} {
		if val, exists := driver[key]; exists {
			if s, isStr := val.(string); isStr {
				lower := strings.ToLower(s)
				if strings.Contains(lower, "microsoft") || strings.Contains(lower, "devops") {
					return true
				}
			}
		}
	}
	return false
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "msft-defender-devops-to-hdf",
		Label:       "Microsoft Defender for DevOps",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			// Must be SARIF: version string + runs array
			ver, hasVer := obj["version"]
			if !hasVer {
				return 0
			}
			if _, isStr := ver.(string); !isStr {
				return 0
			}
			runs, hasRuns := obj["runs"]
			if !hasRuns {
				return 0
			}
			runsArr, isArr := runs.([]any)
			if !isArr {
				return 0
			}
			// Check runs for MSDO-specific tool driver
			for _, run := range runsArr {
				r, isMap := run.(map[string]any)
				if !isMap {
					continue
				}
				tool, hasTool := r["tool"]
				if !hasTool {
					continue
				}
				toolMap, isToolMap := tool.(map[string]any)
				if !isToolMap {
					continue
				}
				driver, hasDriver := toolMap["driver"]
				if !hasDriver {
					continue
				}
				driverMap, isDriverMap := driver.(map[string]any)
				if !isDriverMap {
					continue
				}
				if isMsdoDriver(driverMap) {
					return 0.95
				}
			}
			return 0
		},
	})
}
