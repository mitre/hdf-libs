package dbprotect

import (
	"strings"

	"github.com/mitre/hdf-converters/registry"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "dbprotect-to-hdf",
		Label:       "DBProtect",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if strings.Contains(s, "<dataset") {
				// Higher confidence if metadata/data children present (DBProtect-specific)
				if strings.Contains(s, "<metadata") && strings.Contains(s, "<data") {
					return 1.0
				}
				return 0.8
			}
			return 0
		},
	})
}
