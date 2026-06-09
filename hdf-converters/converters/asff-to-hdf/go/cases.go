package asff

import (
	"regexp"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

type specialCase string

const (
	caseDefault     specialCase = "Default"
	caseSecurityHub specialCase = "SecurityHub"
)

// caseHandler maps an ASFF finding to HDF fields. The default implementation
// in case_default.go handles every slot; specific cases (SecurityHub today,
// Prowler/Trivy/etc. in follow-up beads) override only the slots they need to
// improve. Slots that return a zero value mean "fall back to the default
// implementation."
//
// The slot names mirror heimdall2's externalProductHandler keys so the port
// is auditable.
type caseHandler interface {
	// productName drives EvaluatedBaseline.Title. It runs once per output,
	// not per finding, so it receives the full finding set.
	productName(findings []map[string]any) string

	// findingID drives EvaluatedRequirement.ID (the consolidation key).
	findingID(finding map[string]any) string

	// findingTitle drives EvaluatedRequirement.Title.
	findingTitle(finding map[string]any) string

	// findingImpact returns (impact, handled). handled=false → caller uses default mapping.
	findingImpact(finding map[string]any) (float64, bool)

	// findingNISTTags returns NIST control IDs derived from the finding. Empty
	// slice means "no per-finding tags; caller applies default static tags."
	findingNISTTags(finding map[string]any) []string

	// findingStatus returns the HDF result status. ("", false) means default mapping.
	findingStatus(finding map[string]any) (hdf.ResultStatus, bool)
}

// productArn regexes match heimdall2's whichSpecialCase ordering exactly.
var (
	productSecurityHub = regexp.MustCompile(`^arn:[^:]+:securityhub:[^:]+:[^:]*:product/aws/securityhub$`)
)

func whichSpecialCase(finding map[string]any) specialCase {
	productArn, _ := finding["ProductArn"].(string)
	if productSecurityHub.MatchString(productArn) {
		return caseSecurityHub
	}
	return caseDefault
}

// dispatchAll picks the case handler for a finding-set's first finding. ASFF
// outputs are not currently mixed across product types; if that changes in the
// wild we can dispatch per-finding instead. Additional cases land here as
// follow-up beads (Prowler, Trivy, Inspector, GuardDuty, FirewallManager,
// CMS-InSpec, PreviouslyHDF).
func dispatchAll(findings []map[string]any) caseHandler {
	if len(findings) == 0 {
		return defaultCase{}
	}
	if whichSpecialCase(findings[0]) == caseSecurityHub {
		return securityHubCase{}
	}
	return defaultCase{}
}

// dispatch picks the case handler for one finding. Most slot calls go through
// here so that future per-finding dispatch (heterogeneous ASFF input) drops in
// without changing call sites.
func dispatch(finding map[string]any) caseHandler {
	if whichSpecialCase(finding) == caseSecurityHub {
		return securityHubCase{}
	}
	return defaultCase{}
}
