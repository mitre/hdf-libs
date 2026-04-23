package dbprotect

import (
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
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
			if hdfutil.ExtractXMLRootElement(s) != "dataset" {
				return 0
			}
			// Higher confidence if metadata/data children present (DBProtect-specific)
			if strings.Contains(s, "<metadata") && strings.Contains(s, "<data") {
				return 1.0
			}
			return 0.8
		},
	})
}
