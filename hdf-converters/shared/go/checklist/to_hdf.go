package checklist

import (
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ChecklistToHDF maps the format-neutral Checklist model to HDF Results.
// One EvaluatedBaseline per Stig; one EvaluatedRequirement per Vuln.
//
// v3.2 classification: controlType is derived per-Vuln from the CCI->NIST
// mapping. verificationMethod and applicability are deliberately omitted — the
// checklist format cannot substantiate either (see ckl-to-hdf package doc and
// build-converter skill Step 4d).
//
// Original-format metadata is stashed in HDF extensions/tags so a subsequent
// HDFToChecklist can reproduce the checklist losslessly (round-trip).
func ChecklistToHDF(cl *Checklist, resultsChecksum *hdf.Checksum, converterVersion, generatorName string) *hdf.HDFResults {
	// Checklists carry no per-finding execution timestamp; use one
	// conversion-time value for every result's StartTime and the doc timestamp.
	now := time.Now().UTC()

	baselines := make([]hdf.EvaluatedBaseline, 0, len(cl.Stigs))
	for i := range cl.Stigs {
		baselines = append(baselines, stigToBaseline(&cl.Stigs[i], resultsChecksum, now))
	}

	toolName := "DISA STIG Viewer"
	toolFormat := "CKL"
	if cl.Format == "cklb" {
		toolFormat = "CKLB"
	}

	opts := shared.HDFResultsOptions{
		GeneratorName:    generatorName,
		ConverterVersion: converterVersion,
		ToolName:         toolName,
		ToolFormat:       toolFormat,
		Baselines:        baselines,
	}
	if comp, ok := assetToComponent(&cl.Asset); ok {
		opts.Components = []hdf.Component{comp}
	}
	opts.Timestamp = &now

	results := shared.BuildHDFResults(opts)
	if ext := rootExtensions(cl); len(ext) > 0 {
		results.Extensions = ext
	}
	return results
}

func stigToBaseline(s *Stig, checksum *hdf.Checksum, startTime time.Time) hdf.EvaluatedBaseline {
	requirements := make([]hdf.EvaluatedRequirement, 0, len(s.Vulns))
	for i := range s.Vulns {
		requirements = append(requirements, vulnToRequirement(&s.Vulns[i], startTime))
	}
	bl := hdf.EvaluatedBaseline{
		Name:            "STIG Checklist Scan",
		ResultsChecksum: checksum,
		Requirements:    requirements,
	}
	if s.Title != "" {
		bl.Title = hdfutil.Ptr(s.Title)
	}
	if s.Version != "" {
		bl.Version = hdfutil.Ptr(s.Version)
	}
	if ext := baselineExtensions(s); len(ext) > 0 {
		bl.Extensions = ext
	}
	return bl
}

func vulnToRequirement(v *Vuln, startTime time.Time) hdf.EvaluatedRequirement {
	severity := strings.ToLower(v.Severity)
	impact := hdfutil.SeverityToImpact(severity, 0.5)

	tags := buildTags(v)
	req := hdf.EvaluatedRequirement{
		ID:           v.VulnNum,
		Title:        hdfutil.Ptr(v.RuleTitle),
		Impact:       impact,
		Descriptions: buildDescriptions(v),
		Tags:         tags,
		Results:      []hdf.RequirementResult{buildResult(v, startTime)},
		ControlType:  shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
	}
	if severity != "" {
		sv := hdf.Severity(severity)
		req.Severity = &sv
	}
	return req
}

func buildTags(v *Vuln) map[string]interface{} {
	tags := make(map[string]interface{})
	if len(v.CCIs) > 0 {
		tags["cci"] = v.CCIs
		tags["nist"] = cci.CCIToNIST(v.CCIs)
	} else {
		tags["nist"] = []string{}
	}
	setIfNotEmpty(tags, "rid", v.RuleID)
	setIfNotEmpty(tags, "stig_id", v.RuleVer)
	setIfNotEmpty(tags, "gtitle", v.GroupTitle)
	setIfNotEmpty(tags, "group_id", v.GroupID)
	setIfNotEmpty(tags, "weight", v.Weight)
	// COMMENTS is a field of its own in CKL/CKLB. Merging it into the single HDF
	// message would make it indistinguishable from FINDING_DETAILS on export.
	setIfNotEmpty(tags, "comments", v.Comments)
	setIfNotEmpty(tags, "severity", strings.ToLower(v.Severity))
	if len(v.LegacyIDs) > 0 {
		tags["legacy_ids"] = v.LegacyIDs
	}
	// Preserve rarely-used checklist fields for round-trip without bloating
	// the typed model.
	if len(v.Extra) > 0 {
		meta := make(map[string]interface{}, len(v.Extra))
		for k, val := range v.Extra {
			meta[k] = val
		}
		tags["cklMetadata"] = meta
	}
	return tags
}

func buildDescriptions(v *Vuln) []hdf.Description {
	descriptions := []hdf.Description{
		{Label: "default", Data: hdfutil.StripHTML(v.VulnDiscuss)},
	}
	if v.CheckContent != "" {
		descriptions = append(descriptions, hdf.Description{Label: "check", Data: hdfutil.StripHTML(v.CheckContent)})
	}
	if v.FixText != "" {
		descriptions = append(descriptions, hdf.Description{Label: "fix", Data: hdfutil.StripHTML(v.FixText)})
	}
	return descriptions
}

func buildResult(v *Vuln, startTime time.Time) hdf.RequirementResult {
	result := hdf.RequirementResult{
		Status:   v.Status.ToHDF(),
		CodeDesc: "STIG rule " + v.RuleVer,
		// CKL/CKLB carry no per-finding execution timestamp; use the conversion
		// time so the schema-required startTime is a valid value (the TS mapping
		// uses the same value).
		StartTime: startTime,
	}
	if fd := strings.TrimSpace(v.FindingDetails); fd != "" {
		result.Message = hdfutil.Ptr(fd)
	}
	return result
}

func assetToComponent(a *Asset) (hdf.Component, bool) {
	if a.HostName == "" && a.HostIP == "" && a.HostFQDN == "" {
		return hdf.Component{}, false
	}
	// Name falls back to FQDN then IP so the component always has a usable
	// identity (a checklist may carry only HOST_IP / HOST_FQDN).
	name := a.HostName
	if name == "" {
		name = a.HostFQDN
	}
	if name == "" {
		name = a.HostIP
	}
	c := hdf.Component{Name: name, Type: hdf.Host}
	// HOST_NAME is the short, OS-reported hostname; store it in the dedicated
	// field so it stays distinct from the Name display-fallback and from fqdn.
	if a.HostName != "" {
		c.Hostname = hdfutil.Ptr(a.HostName)
	}
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

// rootExtensions stashes the checklist format + asset fields that have no
// native HDF home, so a round-trip can reconstruct them.
func rootExtensions(cl *Checklist) map[string]interface{} {
	ext := map[string]interface{}{"checklistFormat": orDefault(cl.Format, "ckl")}
	if cl.CKLBVersion != "" {
		ext["cklbVersion"] = cl.CKLBVersion
	}
	// CKLB STIG Viewer document flags: stash only the non-default values so the
	// round-trip restores them (SerializeCKLB defaults the rest to false/0).
	if cl.Active {
		ext["cklbActive"] = true
	}
	if cl.HasPath {
		ext["cklbHasPath"] = true
	}
	if cl.Mode != 0 {
		ext["cklbMode"] = cl.Mode
	}
	assetExtras := map[string]interface{}{}
	setIfNotEmpty(assetExtras, "role", cl.Asset.Role)
	setIfNotEmpty(assetExtras, "assetType", cl.Asset.AssetType)
	setIfNotEmpty(assetExtras, "marking", cl.Asset.Marking)
	setIfNotEmpty(assetExtras, "targetKey", cl.Asset.TargetKey)
	setIfNotEmpty(assetExtras, "techArea", cl.Asset.TechArea)
	setIfNotEmpty(assetExtras, "targetComment", cl.Asset.TargetComment)
	setIfNotEmpty(assetExtras, "webDbSite", cl.Asset.WebDBSite)
	setIfNotEmpty(assetExtras, "webDbInstance", cl.Asset.WebDBInstance)
	setIfNotEmpty(assetExtras, "classification", cl.Asset.Classification)
	if cl.Asset.WebOrDatabase {
		assetExtras["webOrDatabase"] = true
	}
	if len(assetExtras) > 0 {
		ext["assetExtras"] = assetExtras
	}
	return ext
}

func baselineExtensions(s *Stig) map[string]interface{} {
	ext := map[string]interface{}{}
	setIfNotEmpty(ext, "stigid", s.StigID)
	setIfNotEmpty(ext, "uuid", s.UUID)
	setIfNotEmpty(ext, "releaseInfo", s.ReleaseInfo)
	setIfNotEmpty(ext, "displayName", s.DisplayName)
	setIfNotEmpty(ext, "referenceIdentifier", s.ReferenceIdentifier)
	setIfNotEmpty(ext, "classification", s.Classification)
	return ext
}

func setIfNotEmpty(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}
