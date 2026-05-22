// Package ckl converts DISA STIG Viewer checklist (.ckl) XML into HDF Results.
//
// CKL is the manual-fill checklist format produced by the DISA STIG Viewer
// GUI: an assessor records a STATUS (Open / NotAFinding / Not_Reviewed /
// Not_Applicable) per STIG rule. Distinct from XCCDF (the rule/check format);
// CKL is the workflow output.
//
// v3.2 classification fields: controlType is derived per-VULN from the CCI →
// NIST mapping (real per-finding signal). verificationMethod is deliberately
// NOT set — the CKL format does not guarantee whether a finding was assessed
// manually, automated-then-exported, or mixed, so stamping a constant would
// assert a classification the source cannot substantiate. applicability is
// likewise omitted (a Not_Applicable STATUS is an assessment outcome, not a
// baseline applicability marker). See .claude/commands/build-converter.md
// Step 4d.
package ckl

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// maxInputSize caps CKL input at 50MB (entity-expansion + size guard).
const maxInputSize = 50 * 1024 * 1024

// ---------------------------------------------------------------------------
// CKL XML structs (STIG Viewer 2.x/3.x .ckl layout)
// ---------------------------------------------------------------------------

// Checklist is the root <CHECKLIST> element.
type Checklist struct {
	XMLName xml.Name `xml:"CHECKLIST"`
	Asset   Asset    `xml:"ASSET"`
	Stigs   Stigs    `xml:"STIGS"`
}

// Asset holds the target host metadata.
type Asset struct {
	Role      string `xml:"ROLE"`
	AssetType string `xml:"ASSET_TYPE"`
	HostName  string `xml:"HOST_NAME"`
	HostIP    string `xml:"HOST_IP"`
	HostMAC   string `xml:"HOST_MAC"`
	HostFQDN  string `xml:"HOST_FQDN"`
}

// Stigs wraps one or more <iSTIG> blocks (one per STIG benchmark).
type Stigs struct {
	IStigs []IStig `xml:"iSTIG"`
}

// IStig is a single STIG benchmark with its info header and vulns.
type IStig struct {
	StigInfo StigInfo `xml:"STIG_INFO"`
	Vulns    []Vuln   `xml:"VULN"`
}

// StigInfo carries benchmark-level metadata as SI_DATA name/data pairs.
type StigInfo struct {
	SiData []SiData `xml:"SI_DATA"`
}

// SiData is one <SI_DATA> name/data pair.
type SiData struct {
	Name string `xml:"SID_NAME"`
	Data string `xml:"SID_DATA"`
}

// Vuln is a single <VULN> (one STIG rule and its assessed status).
type Vuln struct {
	StigData       []StigData `xml:"STIG_DATA"`
	Status         string     `xml:"STATUS"`
	FindingDetails string     `xml:"FINDING_DETAILS"`
	Comments       string     `xml:"COMMENTS"`
}

// StigData is one <STIG_DATA> attribute/data pair within a VULN.
type StigData struct {
	Attribute string `xml:"VULN_ATTRIBUTE"`
	Data      string `xml:"ATTRIBUTE_DATA"`
}

// ---------------------------------------------------------------------------
// Status mapping
// ---------------------------------------------------------------------------

// statusMapping maps a normalized CKL STATUS to an HDF ResultStatus.
// Keys are lowercased; spaces and underscores are stripped before lookup.
var statusMapping = map[string]hdf.ResultStatus{
	"notafinding":   hdf.Passed,
	"open":          hdf.Failed,
	"notapplicable": hdf.NotApplicable,
	"notreviewed":   hdf.NotReviewed,
}

// mapStatus maps a CKL STATUS string to an HDF ResultStatus. Unrecognized or
// empty values map to NotReviewed (a CKL with no recorded status is, by
// definition, not yet reviewed).
func mapStatus(status string) hdf.ResultStatus {
	normalized := strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(status)), "_", ""), " ", "")
	if s, ok := statusMapping[normalized]; ok {
		return s
	}
	return hdf.NotReviewed
}

// ---------------------------------------------------------------------------
// STIG_DATA / SI_DATA accessors
// ---------------------------------------------------------------------------

// stigDataValue returns the first ATTRIBUTE_DATA for the named VULN_ATTRIBUTE.
func stigDataValue(v *Vuln, attribute string) string {
	for _, sd := range v.StigData {
		if sd.Attribute == attribute {
			return sd.Data
		}
	}
	return ""
}

// stigDataValues returns all ATTRIBUTE_DATA values for the named attribute
// (e.g. CCI_REF, which may repeat).
func stigDataValues(v *Vuln, attribute string) []string {
	var out []string
	for _, sd := range v.StigData {
		if sd.Attribute == attribute && sd.Data != "" {
			out = append(out, sd.Data)
		}
	}
	return out
}

// siDataValue returns the SID_DATA for the named SI_DATA key.
func siDataValue(info *StigInfo, name string) string {
	for _, si := range info.SiData {
		if si.Name == name {
			return si.Data
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

// ConvertCKLToHDF converts a DISA STIG Viewer .ckl document to HDF Results.
func ConvertCKLToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateXMLInput(input, maxInputSize); err != nil {
		return nil, fmt.Errorf("ckl: %w", err)
	}

	var checklist Checklist
	if err := xml.Unmarshal(input, &checklist); err != nil {
		return nil, fmt.Errorf("ckl: failed to parse XML: %w", err)
	}
	if len(checklist.Stigs.IStigs) == 0 {
		return nil, fmt.Errorf("ckl: no <iSTIG> blocks found (not a CKL document?)")
	}

	resultsChecksum := shared.InputChecksum(input)

	baselines := make([]hdf.EvaluatedBaseline, 0, len(checklist.Stigs.IStigs))
	for i := range checklist.Stigs.IStigs {
		baselines = append(baselines, buildBaseline(&checklist.Stigs.IStigs[i], resultsChecksum))
	}

	opts := shared.HDFResultsOptions{
		GeneratorName:    "hdf-converters",
		ConverterVersion: converterVersion,
		ToolName:         "DISA STIG Viewer",
		ToolFormat:       "CKL",
		Baselines:        baselines,
	}
	if comp, ok := buildComponent(&checklist.Asset); ok {
		opts.Components = []hdf.Component{comp}
	}

	now := time.Now().UTC()
	opts.Timestamp = &now

	return shared.BuildHDFResults(opts), nil
}

// buildBaseline converts one <iSTIG> block into an HDF EvaluatedBaseline.
func buildBaseline(istig *IStig, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	title := siDataValue(&istig.StigInfo, "title")
	version := siDataValue(&istig.StigInfo, "version")

	requirements := make([]hdf.EvaluatedRequirement, 0, len(istig.Vulns))
	for i := range istig.Vulns {
		requirements = append(requirements, vulnToRequirement(&istig.Vulns[i]))
	}

	bl := hdf.EvaluatedBaseline{
		Name:            "STIG Checklist Scan",
		ResultsChecksum: checksum,
		Requirements:    requirements,
	}
	if title != "" {
		bl.Title = hdfutil.Ptr(title)
	}
	if version != "" {
		bl.Version = hdfutil.Ptr(version)
	}
	return bl
}

// vulnToRequirement converts one <VULN> into an HDF EvaluatedRequirement.
func vulnToRequirement(v *Vuln) hdf.EvaluatedRequirement {
	id := stigDataValue(v, "Vuln_Num")
	title := stigDataValue(v, "Rule_Title")
	severity := strings.ToLower(stigDataValue(v, "Severity"))
	impact := hdfutil.SeverityToImpact(severity, 0.5)

	tags := buildTags(v)

	req := hdf.EvaluatedRequirement{
		ID:           id,
		Title:        hdfutil.Ptr(title),
		Impact:       impact,
		Descriptions: buildDescriptions(v),
		Tags:         tags,
		Results:      []hdf.RequirementResult{buildResult(v)},
		// controlType from real per-VULN NIST signal; verificationMethod and
		// applicability deliberately omitted (see package doc / skill Step 4d).
		ControlType: shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
	}
	if severity != "" {
		s := hdf.Severity(severity)
		req.Severity = &s
	}
	return req
}

// buildTags builds the requirement tags map with NIST (from CCI) and CCI refs.
// Mirrors xccdf-results-to-hdf: nist/cci are stored as []string so consumers
// (and the controlType derivation) see plain string slices.
func buildTags(v *Vuln) map[string]interface{} {
	tags := make(map[string]interface{})
	cciIDs := stigDataValues(v, "CCI_REF")
	if len(cciIDs) > 0 {
		tags["cci"] = cciIDs
		tags["nist"] = cci.CCIToNIST(cciIDs)
	} else {
		tags["nist"] = []string{}
	}
	return tags
}

// buildDescriptions builds default/check/fix descriptions from STIG_DATA.
func buildDescriptions(v *Vuln) []hdf.Description {
	descriptions := []hdf.Description{
		{Label: "default", Data: hdfutil.StripHTML(stigDataValue(v, "Vuln_Discuss"))},
	}
	if check := stigDataValue(v, "Check_Content"); check != "" {
		descriptions = append(descriptions, hdf.Description{Label: "check", Data: hdfutil.StripHTML(check)})
	}
	if fix := stigDataValue(v, "Fix_Text"); fix != "" {
		descriptions = append(descriptions, hdf.Description{Label: "fix", Data: hdfutil.StripHTML(fix)})
	}
	return descriptions
}

// buildResult builds the single RequirementResult for a VULN, mapping STATUS
// and surfacing FINDING_DETAILS + COMMENTS as the result message.
func buildResult(v *Vuln) hdf.RequirementResult {
	result := hdf.RequirementResult{
		Status:    mapStatus(v.Status),
		CodeDesc:  fmt.Sprintf("STIG rule %s", stigDataValue(v, "Rule_Ver")),
		StartTime: time.Now().UTC(),
	}

	var parts []string
	if fd := strings.TrimSpace(v.FindingDetails); fd != "" {
		parts = append(parts, fd)
	}
	if c := strings.TrimSpace(v.Comments); c != "" {
		parts = append(parts, c)
	}
	if len(parts) > 0 {
		result.Message = hdfutil.Ptr(strings.Join(parts, "\n\n"))
	}
	return result
}

// buildComponent builds an HDF Host component from the CKL <ASSET> block.
// Returns ok=false when the asset carries no identifiable host.
func buildComponent(a *Asset) (hdf.Component, bool) {
	if a.HostName == "" && a.HostIP == "" && a.HostFQDN == "" {
		return hdf.Component{}, false
	}
	c := hdf.Component{Name: a.HostName, Type: hdf.Host}
	if a.HostIP != "" {
		c.IPAddress = hdfutil.Ptr(a.HostIP)
	}
	if a.HostFQDN != "" {
		c.FQDN = hdfutil.Ptr(a.HostFQDN)
	}
	if a.HostMAC != "" {
		c.MACAddress = hdfutil.Ptr(a.HostMAC)
	}
	return c, true
}
