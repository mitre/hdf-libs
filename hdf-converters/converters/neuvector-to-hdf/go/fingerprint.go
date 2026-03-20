package neuvector

import "github.com/mitre/hdf-converters/registry"

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "neuvector-to-hdf",
		Label:       "NeuVector",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			report, hasReport := obj["report"]
			if !hasReport {
				return 0
			}
			reportMap, isMap := report.(map[string]any)
			if !isMap {
				return 0
			}
			vulns, hasVulns := reportMap["vulnerabilities"]
			if !hasVulns {
				return 0
			}
			vulnArr, isArr := vulns.([]any)
			if !isArr {
				return 0
			}
			if len(vulnArr) == 0 {
				return 0.7
			}
			first, isFirstMap := vulnArr[0].(map[string]any)
			if !isFirstMap {
				return 0.5
			}
			name, hasName := first["name"]
			pkg, hasPkg := first["package_name"]
			if hasName && hasPkg {
				_, nameIsStr := name.(string)
				_, pkgIsStr := pkg.(string)
				if nameIsStr && pkgIsStr {
					return 1.0
				}
			}
			return 0.5
		},
	})
}
