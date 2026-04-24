package fortify

import (
	"regexp"
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

var fvdlVersionRe = regexp.MustCompile(`<FVDL\b[^>]*\bversion="([^"]+)"`)

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "fortify-to-hdf",
		Label:       "Fortify",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			if hdfutil.ExtractXMLRootElement(s) != "FVDL" {
				return 0
			}
			// Higher confidence with Fortify namespace
			if strings.Contains(s, "xmlns.fortify.com") {
				return 1.0
			}
			return 0.95
		},
		DetectVersion: func(input any) string {
			s, ok := input.(string)
			if !ok {
				return ""
			}
			m := fvdlVersionRe.FindStringSubmatch(s)
			if len(m) > 1 {
				return m[1]
			}
			return ""
		},
	})
}
