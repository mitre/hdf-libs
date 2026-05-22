package checklist

import (
	"encoding/json"
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// HDFToChecklist maps HDF Results back to the format-neutral Checklist model.
//
// When the HDF carries checklist passthrough (extensions/tags written by
// ChecklistToHDF — i.e. the HDF originated from a CKL/CKLB), the original
// fields are reproduced losslessly. For arbitrary HDF from any other tool, the
// required checklist fields are synthesized best-effort (id->Vuln_Num,
// tags->Rule_ID/CCI, nist->CCI reverse, status reverse) with safe defaults, so
// any HDF yields a valid checklist.
func HDFToChecklist(input []byte) (*Checklist, error) {
	var results hdf.HDFResults
	if err := json.Unmarshal(input, &results); err != nil {
		return nil, fmt.Errorf("hdf to checklist: parse HDF: %w", err)
	}
	if len(results.Baselines) == 0 {
		return nil, fmt.Errorf("hdf to checklist: HDF has no baselines")
	}

	cl := &Checklist{}
	applyRootExtensions(cl, results.Extensions)
	cl.Asset = buildAsset(&results, cl)

	for i := range results.Baselines {
		cl.Stigs = append(cl.Stigs, baselineToStig(&results.Baselines[i]))
	}
	return cl, nil
}

func applyRootExtensions(cl *Checklist, ext map[string]interface{}) {
	cl.Format = orDefault(strVal(ext, "checklistFormat"), "ckl")
	cl.CKLBVersion = strVal(ext, "cklbVersion")
}

func buildAsset(results *hdf.HDFResults, cl *Checklist) Asset {
	var a Asset
	if len(results.Components) > 0 {
		c := results.Components[0]
		a.HostName = c.Name
		a.HostIP = derefStr(c.IPAddress)
		a.HostFQDN = derefStr(c.FQDN)
		a.HostMAC = derefStr(c.MACAddress)
	}
	// Merge asset extras from root extensions (round-trip).
	if extras, ok := mapVal(results.Extensions, "assetExtras"); ok {
		a.Role = strVal(extras, "role")
		a.AssetType = strVal(extras, "assetType")
		a.Marking = strVal(extras, "marking")
		a.TargetKey = strVal(extras, "targetKey")
		a.TechArea = strVal(extras, "techArea")
		a.TargetComment = strVal(extras, "targetComment")
		a.WebDBSite = strVal(extras, "webDbSite")
		a.WebDBInstance = strVal(extras, "webDbInstance")
		a.Classification = strVal(extras, "classification")
		if b, ok := extras["webOrDatabase"].(bool); ok {
			a.WebOrDatabase = b
		}
	}
	return a
}

func baselineToStig(bl *hdf.EvaluatedBaseline) Stig {
	stig := Stig{
		Title:   derefStr(bl.Title),
		Version: derefStr(bl.Version),
	}
	// Round-trip metadata from baseline extensions.
	stig.StigID = strVal(bl.Extensions, "stigid")
	stig.UUID = strVal(bl.Extensions, "uuid")
	stig.ReleaseInfo = strVal(bl.Extensions, "releaseInfo")
	stig.DisplayName = strVal(bl.Extensions, "displayName")
	stig.ReferenceIdentifier = strVal(bl.Extensions, "referenceIdentifier")
	stig.Classification = strVal(bl.Extensions, "classification")
	if stig.StigID == "" {
		stig.StigID = stig.Title
	}

	for i := range bl.Requirements {
		stig.Vulns = append(stig.Vulns, requirementToVuln(&bl.Requirements[i]))
	}
	return stig
}

func requirementToVuln(req *hdf.EvaluatedRequirement) Vuln {
	tags := req.Tags
	v := Vuln{
		VulnNum:        req.ID,
		RuleID:         tagStr(tags, "rid"),
		RuleVer:        tagStr(tags, "stig_id"),
		GroupID:        orDefault(tagStr(tags, "group_id"), req.ID),
		GroupTitle:     tagStr(tags, "gtitle"),
		RuleTitle:      derefStr(req.Title),
		Weight:         tagStr(tags, "weight"),
		Severity:       resolveSeverity(req, tags),
		CCIs:           resolveCCIs(tags),
		LegacyIDs:      tagStrSlice(tags, "legacy_ids"),
		Status:         StatusFromHDF(firstResultStatus(req)),
		FindingDetails: derefStr(firstResultMessage(req)),
		Extra:          extractCklMetadata(tags),
	}
	v.VulnDiscuss = descByLabel(req.Descriptions, "default")
	v.CheckContent = descByLabel(req.Descriptions, "check")
	v.FixText = descByLabel(req.Descriptions, "fix")
	return v
}

// resolveSeverity prefers the round-tripped tags.severity, else derives from
// impact thresholds (the inverse of SeverityToImpact's standard mapping).
func resolveSeverity(req *hdf.EvaluatedRequirement, tags map[string]interface{}) string {
	if s := tagStr(tags, "severity"); s != "" {
		return s
	}
	if req.Severity != nil && *req.Severity != "" {
		return strings.ToLower(string(*req.Severity))
	}
	switch {
	case req.Impact >= 0.7:
		return "high"
	case req.Impact >= 0.4:
		return "medium"
	case req.Impact > 0:
		return "low"
	default:
		return ""
	}
}

// resolveCCIs prefers explicit tags.cci, else reverses tags.nist via NISTToCCI.
func resolveCCIs(tags map[string]interface{}) []string {
	if ccis := tagStrSlice(tags, "cci"); len(ccis) > 0 {
		return ccis
	}
	if nist := shared.NISTTagsFromMap(tags); len(nist) > 0 {
		if ccis := cci.NISTToCCI(nist); len(ccis) > 0 {
			return ccis
		}
	}
	return nil
}

func extractCklMetadata(tags map[string]interface{}) map[string]string {
	meta, ok := mapVal(tags, "cklMetadata")
	if !ok {
		return nil
	}
	out := make(map[string]string, len(meta))
	for k, v := range meta {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// --- tag / extension accessors (tolerate string, []string, []interface{}) ---

func firstResultStatus(req *hdf.EvaluatedRequirement) hdf.ResultStatus {
	if len(req.Results) > 0 {
		return req.Results[0].Status
	}
	return hdf.NotReviewed
}

func firstResultMessage(req *hdf.EvaluatedRequirement) *string {
	if len(req.Results) > 0 {
		return req.Results[0].Message
	}
	return nil
}

func descByLabel(descs []hdf.Description, label string) string {
	for _, d := range descs {
		if d.Label == label {
			return d.Data
		}
	}
	return ""
}

func tagStr(tags map[string]interface{}, key string) string {
	return strVal(tags, key)
}

func tagStrSlice(tags map[string]interface{}, key string) []string {
	if tags == nil {
		return nil
	}
	switch v := tags[key].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func strVal(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func mapVal(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	if m == nil {
		return nil, false
	}
	if mv, ok := m[key].(map[string]interface{}); ok {
		return mv, true
	}
	return nil, false
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
