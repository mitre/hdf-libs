// Package checklist provides a format-neutral model for DISA STIG Viewer
// checklists and the mapping between that model and HDF Results. Both the CKL
// (XML, STIG Viewer 2.x) and CKLB (JSON, STIG Viewer 3.x) formats carry the
// same semantic content in different shapes; this package centralizes the
// HDF<->checklist mapping so the four converter directions (ckl-to-hdf,
// cklb-to-hdf, hdf-to-ckl, hdf-to-cklb) share one implementation.
//
// Flow:
//
//	ckl-to-hdf:   ParseCKL  -> Checklist -> ChecklistToHDF
//	cklb-to-hdf:  ParseCKLB -> Checklist -> ChecklistToHDF
//	hdf-to-ckl:   HDFToChecklist -> Checklist -> SerializeCKL
//	hdf-to-cklb:  HDFToChecklist -> Checklist -> SerializeCKLB
package checklist

// CheckStatus is the canonical, format-neutral assessment status. The CKL
// spelling is used as the canonical form; per-format adapters translate to/from
// CKLB's snake_case and HDF's Result_Status.
type CheckStatus string

const (
	StatusOpen          CheckStatus = "Open"
	StatusNotAFinding   CheckStatus = "NotAFinding"
	StatusNotReviewed   CheckStatus = "Not_Reviewed"
	StatusNotApplicable CheckStatus = "Not_Applicable"
)

// Checklist is the format-neutral model of a STIG Viewer checklist.
type Checklist struct {
	Asset Asset
	Stigs []Stig
	// Format records the origin format ("ckl" or "cklb") so a round-trip can
	// preserve it via HDF extensions. Empty when synthesized from arbitrary HDF.
	Format string
	// CKLBVersion is the cklb_version string (CKLB only); empty for CKL.
	CKLBVersion string
	// Active, HasPath, and Mode are CKLB-only STIG Viewer document flags. They
	// carry no HDF meaning but must round-trip losslessly, so they ride the HDF
	// extensions channel like Format/CKLBVersion. Default zero values for CKL or
	// HDF-synthesized checklists.
	Active  bool
	HasPath bool
	Mode    int
}

// Asset is the target host metadata (CKL <ASSET> / CKLB target_data).
type Asset struct {
	Role           string
	AssetType      string
	HostName       string
	HostIP         string
	HostMAC        string
	HostFQDN       string
	TargetKey      string
	Marking        string
	WebOrDatabase  bool
	WebDBSite      string
	WebDBInstance  string
	TechArea       string
	TargetComment  string
	Classification string
}

// Stig is one STIG benchmark within a checklist (CKL <iSTIG> / CKLB stigs[]).
type Stig struct {
	StigID              string
	Title               string
	DisplayName         string
	Version             string
	ReleaseInfo         string
	UUID                string
	ReferenceIdentifier string
	Classification      string
	Vulns               []Vuln
}

// Vuln is one STIG rule and its assessed status (CKL <VULN> / CKLB rule).
type Vuln struct {
	VulnNum        string
	RuleID         string
	RuleVer        string
	GroupID        string
	GroupTitle     string
	Severity       string
	RuleTitle      string
	VulnDiscuss    string
	CheckContent   string
	FixText        string
	Weight         string
	Classification string
	CCIs           []string
	LegacyIDs      []string
	Status         CheckStatus
	FindingDetails string
	Comments       string
	// SeverityOverride and SeverityJustification carry an assessor's manual
	// severity adjustment: the CKL SEVERITY_OVERRIDE / SEVERITY_JUSTIFICATION
	// pair and the CKLB rule.overrides.severity object. On export they are
	// synthesized from an HDF impact-bearing statusOverride (risk adjustment).
	SeverityOverride      string
	SeverityJustification string
	// Extra holds the rarely-used STIG_DATA / rule fields (false_positives,
	// mitigations, responsibility, etc.) keyed by canonical name, preserved for
	// round-trip fidelity without bloating the typed model.
	Extra map[string]string
}
