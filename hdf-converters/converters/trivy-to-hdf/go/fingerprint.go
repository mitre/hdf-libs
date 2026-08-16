package trivy

import (
	"strconv"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
)

// The fingerprint matches native Trivy JSON only, keying on markers the delegate
// formats (SARIF, CycloneDX, ASFF, GitLab) lack: a numeric SchemaVersion plus
// ArtifactName + ArtifactType. Trivy's other output shapes auto-detect to their
// own converters; the router's delegation serves the explicit `--from trivy`.
func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "trivy-to-hdf",
		Label:       "Trivy",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			obj, ok := input.(map[string]any)
			if !ok {
				return 0
			}
			if _, isNum := obj["SchemaVersion"].(float64); !isNum {
				return 0
			}
			_, hasName := obj["ArtifactName"]
			_, hasType := obj["ArtifactType"]
			if hasName && hasType {
				return 0.95
			}
			return 0
		},
		DetectVersion: func(input any) string {
			if obj, ok := input.(map[string]any); ok {
				if sv, isNum := obj["SchemaVersion"].(float64); isNum {
					return strconv.Itoa(int(sv))
				}
			}
			return ""
		},
	})
}
