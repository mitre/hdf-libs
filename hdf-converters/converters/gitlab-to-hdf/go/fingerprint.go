package gitlab_to_hdf

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "gitlab-to-hdf",
		Label:       "GitLab",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			vulns, exists := obj["vulnerabilities"]
			if !exists {
				return 0
			}
			if _, isArr := vulns.([]any); !isArr {
				return 0
			}
			// Strong signal: scan object with type field (GitLab Security Report schema)
			if scan, hasScan := obj["scan"]; hasScan {
				if scanMap, isMap := scan.(map[string]any); isMap {
					if t, hasType := scanMap["type"]; hasType {
						if _, isStr := t.(string); isStr {
							return 0.9
						}
					}
					// Has scan but no type — still likely GitLab
					return 0.7
				}
			}
			// Weak signal: just vulnerabilities[] (could be GitLab or other tools)
			return 0.5
		},
	})
}
