package ckl

import (
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "ckl-to-hdf",
		Label:       "CKL (DISA STIG Viewer checklist)",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			// CKL checklist root element. ExtractXMLRootElement strips
			// namespace prefixes automatically.
			if hdfutil.ExtractXMLRootElement(s) == "CHECKLIST" {
				return 1.0
			}
			return 0
		},
	})
}
