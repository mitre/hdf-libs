package burpsuite

import (
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go"
)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "burpsuite-to-hdf",
		Label:       "Burp Suite",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if hdfutil.ExtractXMLRootElement(s) != "issues" {
				return 0
			}
			// burpVersion attribute is a strong signal
			if strings.Contains(s, "burpVersion") {
				return 1.0
			}
			return 0.7
		},
	})
}
