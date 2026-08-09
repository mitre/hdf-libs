package checklist

import (
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
	if err := shared.DecodeHDF(input, &results); err != nil {
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
	cl.Active = boolVal(ext, "cklbActive")
	cl.HasPath = boolVal(ext, "cklbHasPath")
	cl.Mode = intVal(ext, "cklbMode")
}

func buildAsset(results *hdf.HDFResults, cl *Checklist) Asset {
	var a Asset
	if len(results.Components) > 0 {
		c := results.Components[0]
		// Prefer the dedicated hostname. For HDF produced before hostname existed,
		// fall back to Name — but only when Name holds a real short name, not when
		// it merely mirrors the fqdn/ip fallback the old converter stored there
		// (which would fabricate a HOST_NAME the source never had).
		if c.Hostname != nil {
			a.HostName = *c.Hostname
		} else if c.Name != derefStr(c.FQDN) && c.Name != derefStr(c.IPAddress) {
			a.HostName = c.Name
		}
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
	sevOverride, sevJust := overrideSeverity(req)
	v := Vuln{
		VulnNum:               req.ID,
		RuleID:                tagStr(tags, "rid"),
		RuleVer:               tagStr(tags, "stig_id"),
		GroupID:               orDefault(tagStr(tags, "group_id"), req.ID),
		GroupTitle:            tagStr(tags, "gtitle"),
		RuleTitle:             derefStr(req.Title),
		Weight:                tagStr(tags, "weight"),
		Severity:              resolveSeverity(req, tags),
		CCIs:                  resolveCCIs(tags),
		LegacyIDs:             tagStrSlice(tags, "legacy_ids"),
		Status:                StatusFromHDF(effectiveOrRawStatus(req)),
		FindingDetails:        composeFindingDetails(req),
		Comments:              composeComments(tags, req),
		SeverityOverride:      sevOverride,
		SeverityJustification: sevJust,
		Extra:                 extractCklMetadata(tags),
	}
	v.VulnDiscuss = descByLabel(req.Descriptions, "default")
	v.CheckContent = descByLabel(req.Descriptions, "check")
	v.FixText = descByLabel(req.Descriptions, "fix")
	return v
}

// effectiveOrRawStatus drives the exported checklist STATUS from the resolved
// post-override status when the HDF carries one, falling back to the raw first
// result. A waived/attested/false-positive finding thus exports its governing
// posture (Not_Applicable / NotAFinding) rather than the pre-override Open.
func effectiveOrRawStatus(req *hdf.EvaluatedRequirement) hdf.ResultStatus {
	if req.EffectiveStatus != nil && *req.EffectiveStatus != "" {
		return *req.EffectiveStatus
	}
	return firstResultStatus(req)
}

// composeFindingDetails builds FINDING_DETAILS from every result's status,
// codeDesc, and message — not just results[0].message — so multi-test
// requirements and the per-test assessment narrative survive export.
func composeFindingDetails(req *hdf.EvaluatedRequirement) string {
	if len(req.Results) == 0 {
		return ""
	}
	segments := make([]string, 0, len(req.Results))
	for i := range req.Results {
		r := &req.Results[i]
		var body []string
		if cd := strings.TrimSpace(r.CodeDesc); cd != "" {
			body = append(body, cd)
		}
		if r.Message != nil {
			if msg := strings.TrimSpace(*r.Message); msg != "" && (len(body) == 0 || msg != body[0]) {
				body = append(body, msg)
			}
		}
		seg := "[" + string(r.Status) + "]"
		if len(body) > 0 {
			seg += " " + strings.Join(body, "\n")
		}
		segments = append(segments, seg)
	}
	return strings.Join(segments, "\n\n")
}

// composeComments merges the round-tripped COMMENTS (tags.comments) with the
// provenance of any status overrides / disposition governing this requirement.
func composeComments(tags map[string]interface{}, req *hdf.EvaluatedRequirement) string {
	parts := make([]string, 0, 2)
	if c := tagStr(tags, "comments"); c != "" {
		parts = append(parts, c)
	}
	if prov := overrideProvenance(req); prov != "" {
		parts = append(parts, prov)
	}
	return strings.Join(parts, "\n\n")
}

// overrideProvenance renders the audit trail of every status override (most
// recent first per schema) as free text for COMMENTS. When no overrides are
// recorded but a disposition is, it notes the disposition type alone.
func overrideProvenance(req *hdf.EvaluatedRequirement) string {
	if len(req.StatusOverrides) > 0 {
		lines := make([]string, 0, len(req.StatusOverrides))
		for i := range req.StatusOverrides {
			lines = append(lines, formatOverride(&req.StatusOverrides[i]))
		}
		return strings.Join(lines, "\n")
	}
	if req.Disposition != nil && *req.Disposition != "" {
		return "Disposition: " + string(*req.Disposition)
	}
	return ""
}

func formatOverride(o *hdf.StatusOverride) string {
	s := "Override [" + string(o.Type) + "]"
	if o.Reason != "" {
		s += ": " + o.Reason
	}
	var meta []string
	if id := o.AppliedBy.Identifier; id != "" {
		meta = append(meta, "by "+id)
	}
	if !o.AppliedAt.IsZero() {
		meta = append(meta, "applied "+formatOverrideTime(o.AppliedAt))
	}
	if !o.ExpiresAt.IsZero() {
		meta = append(meta, "expires "+formatOverrideTime(o.ExpiresAt))
	}
	if len(meta) > 0 {
		s += " (" + strings.Join(meta, ", ") + ")"
	}
	return s
}

func formatOverrideTime(t time.Time) string {
	return hdfutil.NormalizeTimestamp(t).Format(time.RFC3339Nano)
}

// overrideSeverity derives the checklist severity override (SEVERITY_OVERRIDE /
// overrides.severity) from the first impact-bearing status override — a risk
// adjustment restates the qualitative severity, its reason the justification.
func overrideSeverity(req *hdf.EvaluatedRequirement) (severity, justification string) {
	for i := range req.StatusOverrides {
		o := &req.StatusOverrides[i]
		if o.Impact != nil {
			return qualSeverityFromImpact(o.Impact.Value), o.Reason
		}
	}
	return "", ""
}

// qualSeverityFromImpact maps an impact score to STIG's qualitative severity
// bucket, inverse of the standard SeverityToImpact mapping.
func qualSeverityFromImpact(impact float64) string {
	switch {
	case impact >= 0.7:
		return "high"
	case impact >= 0.4:
		return "medium"
	default:
		return "low"
	}
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

func boolVal(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	b, ok := m[key].(bool)
	return ok && b
}

// intVal reads a JSON number back as int. JSON round-trips numbers as float64,
// so accept both float64 (post-unmarshal) and int (in-memory).
func intVal(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	switch n := m[key].(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
