package junit

import (
	"regexp"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// checkovTestCaseName matches the "[SEVERITY][CHECK_ID]" prefix Checkov packs into
// JUnit testcase names (a CKV/CKV2 check id for IaC, a CVE id for SCA). Only the
// prefix is keyed on, so reworded check descriptions still match.
var checkovTestCaseName = regexp.MustCompile(`^\[[A-Z]+\]\[(?:CKV2?_[A-Z0-9_]+|CVE-\d{4}-\d+)\]`)

// isCheckovTestCaseName reports whether a JUnit testcase name carries Checkov's
// bracketed severity and check id prefix.
func isCheckovTestCaseName(name string) bool {
	return checkovTestCaseName.MatchString(name)
}

func init() {
	registry.Register(registry.ConverterFingerprint{
		ID:          "junit-to-hdf",
		Label:       "JUnit",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyXML,
		OutputType:  registry.OutputResults,
		Fingerprint: func(input any) float64 {
			s, ok := input.(string)
			if !ok {
				return 0
			}
			root := hdfutil.ExtractXMLRootElement(s)
			if root == "testsuites" || root == "testsuite" {
				return 1.0
			}
			return 0
		},
	})
}
