// Package hdftoocsf exports HDF Results as OCSF (Open Cybersecurity Schema
// Framework) Finding NDJSON, per the ADR-0002 addendum (HDF → OCSF, wvc3.5).
//
// One OCSF Finding is emitted per Evaluated_Requirement: a CVE finding →
// Vulnerability Finding (class_uid 2002), any other → Compliance Finding
// (class_uid 2003), both under the Findings category (2). Pinned to OCSF v1.8.0.
//
// Status model (raw-primary): compliance.status_id carries the RAW verdict
// (Pass/Warning/Fail) — a failed control stays Fail even when waived, so a
// consumer never mistakes a waiver for a pass. The acceptance axis rides the
// base finding status_id: a raw-failing finding that an override drove
// non-failing (waiver/falsePositive/attestation) → 3 Suppressed, everything
// else → 1 New. A riskAdjustment / operationalRequirement / poam that leaves the
// finding failing stays New — still actionable, only re-scored. The exact
// override type/justification/chain is preserved losslessly in
// unmapped.hdf_requirement (+ a human comment). The canonical "still actionable"
// query is compliance.status_id = 3 (Fail) AND status_id = 1 (New).
//
// Generic JSON access, the status roll-up, field extraction, and the canonical
// byte-identical line encoder are shared with the other exporters via exportmap;
// only OCSF-specific shaping lives here.
package hdftoocsf

import (
	"strconv"
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	ocsfVersion        = "1.8.0"
	categoryFindings   = 2
	classCompliance    = 2003
	classVulnerability = 2002
	activityCreate     = 1
	statusNew          = 1 // finding lifecycle: New
	statusSuppressed   = 3 // finding lifecycle: Suppressed (adjudicated/waived)
)

// ConvertHDFToOCSF converts an HDF Results document to OCSF Finding NDJSON.
func ConvertHDFToOCSF(input []byte, converterVersion string) ([]byte, error) {
	return exportmap.Export(input, "hdf-to-ocsf",
		func(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}) map[string]interface{} {
			return buildFinding(req, baseline, docTimestamp, tool, generator, component, converterVersion)
		})
}

// buildFinding maps one Evaluated_Requirement to a single OCSF Finding object.
func buildFinding(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}, converterVersion string) map[string]interface{} {
	st := exportmap.StatusOf(req)
	cvssList, hasCVSS := exportmap.AsSlice(req["cvss"])
	hasCVSS = hasCVSS && len(cvssList) > 0
	title := exportmap.GetStr(req, "title")
	controlID := exportmap.GetStr(req, "id")

	class := classCompliance
	if hasCVSS {
		class = classVulnerability
	}

	findingInfo := map[string]interface{}{"uid": controlID}
	exportmap.SetIf(findingInfo, "title", title)
	exportmap.SetIf(findingInfo, "desc", exportmap.DefaultDescription(req))
	// A Vulnerability Finding (class 2002) has no compliance.checks[] field, so a
	// CVE that also carries NIST/CCI framework tags would otherwise lose that
	// mapping to unmapped only. Surface it on finding_info.tags (OCSF's queryable
	// key/value tag surface). Compliance Findings keep the native compliance.checks[].
	if hasCVSS {
		if tags := frameworkTags(req); len(tags) > 0 {
			findingInfo["tags"] = tags
		}
	}

	finding := map[string]interface{}{
		"category_uid": categoryFindings,
		"class_uid":    class,
		"type_uid":     class*100 + activityCreate,
		"activity_id":  activityCreate,
		"severity_id":  severityID(req),
		"status_id":    overrideStatusID(st),
		"metadata":     buildMetadata(tool, generator, converterVersion),
		"finding_info": findingInfo,
		"unmapped":     map[string]interface{}{"hdf_requirement": req},
	}
	// time is OCSF-required: fall back to 0 (epoch sentinel) when the source
	// carries no parseable timestamp, so the record stays schema-valid. Valid
	// HDF always has a result startTime, so this only affects malformed input.
	ms, _ := exportmap.EpochMillis(exportmap.FirstResultStartTime(req, docTimestamp))
	finding["time"] = ms
	exportmap.SetIf(finding, "comment", overrideComment(req))
	if device := buildDevice(component); device != nil {
		finding["device"] = device
	}

	// Surface the check evidence and raw source data into their first-class OCSF
	// (base_event) homes instead of leaving them only in unmapped: the raw tool
	// blob → raw_data, the assertion text → message, per-result codeDesc/message/
	// status → evidences[], and the precise HDF status (which the collapsed
	// compliance.status_id loses for notApplicable/notReviewed/error) →
	// status_detail. status_detail carries the effective/rollup status so it also
	// reflects an override (e.g. a waived fail reads "passed").
	exportmap.SetIf(finding, "raw_data", exportmap.GetStr(req, "code"))
	exportmap.SetIf(finding, "message", firstResultMessage(req))
	if ev := buildEvidences(req); len(ev) > 0 {
		finding["evidences"] = ev
	}
	exportmap.SetIf(finding, "status_detail", st.Rollup)
	// The "fix"-labeled description is real remediation guidance; give it the
	// first-class Finding remediation home (Vulnerability Findings also get a
	// per-vuln remediation + fix_available below).
	if rem := remediationText(req); rem != "" {
		finding["remediation"] = map[string]interface{}{"desc": rem}
	}

	if hasCVSS {
		finding["vulnerabilities"] = buildVulnerabilities(cvssList, req)
	} else {
		finding["compliance"] = buildCompliance(req, baseline, title, st.Raw)
	}
	return finding
}

// severityID maps an HDF requirement to the OCSF severity_id enum
// (0 Unknown, 1 Informational … 5 Critical), preferring numeric impact.
func severityID(req map[string]interface{}) int {
	if impact, ok := req["impact"].(float64); ok {
		return severityIDFromString(hdfutil.ImpactToSeverity(impact))
	}
	return severityIDFromString(exportmap.GetStr(req, "severity"))
}

func severityIDFromString(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "informational", "info", "none":
		return 1
	default:
		return 0
	}
}

// complianceStatusID maps a raw HDF status to the OCSF compliance.status_id
// enum (1 Pass, 2 Warning, 3 Fail). error/notApplicable/notReviewed → Warning;
// the exact HDF status is preserved verbatim in unmapped.hdf_requirement.
func complianceStatusID(rawStatus string) int {
	switch rawStatus {
	case "passed":
		return 1
	case "failed":
		return 3
	default: // error, notApplicable, notReviewed
		return 2
	}
}

// complianceStatusCaption returns the OCSF caption for a compliance.status_id,
// carried in the sibling compliance.status string. OCSF convention is that the
// enum sibling string is the caption of the enum value; the HDF-native status
// (which distinguishes notApplicable/notReviewed/error, all → Warning) is
// preserved losslessly in unmapped.hdf_requirement.
func complianceStatusCaption(statusID int) string {
	switch statusID {
	case 1:
		return "Pass"
	case 3:
		return "Fail"
	default:
		return "Warning"
	}
}

// overrideStatusID encodes the acceptance axis onto the base finding status_id:
// a raw-failing finding that an override drove non-failing (waiver/falsePositive/
// attestation) → 3 Suppressed; everything else → 1 New (actionable). A
// riskAdjustment / operationalRequirement / poam that leaves the finding failing
// stays New — it is still the operator's problem, only its impact is re-scored.
func overrideStatusID(st exportmap.Status) int {
	if st.Suppressed {
		return statusSuppressed
	}
	return statusNew
}

// overrideComment builds a human-readable governance note from the disposition
// (override type) and the governing override's required free-text `reason`.
// (Status_Override.justification is an optional structured controlled-vocabulary
// object, not the human rationale — reason is the field to surface.)
func overrideComment(req map[string]interface{}) string {
	disposition := exportmap.GetStr(req, "disposition")
	overrides, _ := exportmap.AsSlice(req["statusOverrides"])
	if disposition == "" && len(overrides) == 0 {
		return ""
	}
	reason := ""
	if len(overrides) > 0 {
		if first, ok := exportmap.AsMap(overrides[0]); ok {
			reason = exportmap.GetStr(first, "reason")
		}
	}
	switch {
	case disposition != "" && reason != "":
		return disposition + ": " + reason
	case disposition != "":
		return disposition
	default:
		return reason
	}
}

// buildMetadata builds the OCSF-required metadata object. metadata.product is
// also required, so it identifies the source scanning tool when present and
// falls back to this exporter's own identity otherwise (never omitted).
func buildMetadata(tool, generator map[string]interface{}, converterVersion string) map[string]interface{} {
	metadata := map[string]interface{}{"version": ocsfVersion}
	name := exportmap.GetStr(tool, "name")
	version := exportmap.GetStr(tool, "version")
	vendor := exportmap.GetStr(tool, "format")
	if name == "" && generator != nil {
		name = exportmap.GetStr(generator, "name")
		version = exportmap.GetStr(generator, "version")
	}
	if name == "" {
		name = "hdf-to-ocsf"
		version = converterVersion
		vendor = ""
	}
	product := map[string]interface{}{"name": name}
	exportmap.SetIf(product, "version", version)
	exportmap.SetIf(product, "vendor_name", vendor)
	metadata["product"] = product
	return metadata
}

func buildDevice(component map[string]interface{}) map[string]interface{} {
	if component == nil {
		return nil
	}
	device := map[string]interface{}{"type_id": 0}
	exportmap.SetIf(device, "name", exportmap.GetStr(component, "name"))
	exportmap.SetIf(device, "hostname", exportmap.GetStr(component, "fqdn"))
	exportmap.SetIf(device, "ip", exportmap.GetStr(component, "ipAddress"))
	exportmap.SetIf(device, "uid", exportmap.GetStr(component, "componentId"))
	if osName := exportmap.GetStr(component, "osName"); osName != "" {
		os := map[string]interface{}{"name": osName, "type_id": osTypeID(osName)}
		exportmap.SetIf(os, "version", exportmap.GetStr(component, "osVersion"))
		device["os"] = os
	}
	// device requires at least one identifying attribute
	if len(device) == 1 { // only type_id
		return nil
	}
	return device
}

// osTypeID classifies an OS name onto the OCSF os.type_id enum
// (100 Windows, 200 Linux, 300 macOS, 0 Unknown).
func osTypeID(osName string) int {
	n := strings.ToLower(osName)
	switch {
	case containsAny(n, "windows"):
		return 100
	case containsAny(n, "linux", "rhel", "red hat", "ubuntu", "centos", "debian", "fedora", "suse"):
		return 200
	case containsAny(n, "mac", "darwin", "os x"):
		return 300
	default:
		return 0
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// frameworkTags builds OCSF finding_info.tags (a key_value_object list) from the
// requirement's NIST/CCI mappings, e.g. {name:"nist", values:["SI-2","RA-5"]}.
// Only non-empty mappings are emitted.
func frameworkTags(req map[string]interface{}) []interface{} {
	tags, _ := exportmap.AsMap(req["tags"])
	var out []interface{}
	for _, key := range []string{"nist", "cci"} {
		if vals := exportmap.StringSlice(tags[key]); len(vals) > 0 {
			out = append(out, map[string]interface{}{"name": key, "values": vals})
		}
	}
	return out
}

func buildCompliance(req, baseline map[string]interface{}, title, rawStatus string) map[string]interface{} {
	statusID := complianceStatusID(rawStatus)
	compliance := map[string]interface{}{
		"status_id": statusID,
		"status":    complianceStatusCaption(statusID), // OCSF caption of status_id
	}
	controlID := exportmap.GetStr(req, "id")
	exportmap.SetIf(compliance, "control", controlID)

	baselineName := exportmap.GetStr(baseline, "name")
	tags, _ := exportmap.AsMap(req["tags"])
	nist := exportmap.StringSlice(tags["nist"])
	cci := exportmap.StringSlice(tags["cci"])

	var standards []interface{}
	if baselineName != "" {
		standards = append(standards, baselineName)
	}
	if len(nist) > 0 {
		standards = append(standards, "NIST SP 800-53")
	}
	if len(cci) > 0 {
		standards = append(standards, "CCI")
	}
	if len(standards) > 0 {
		compliance["standards"] = standards
	}

	// checks[]: one per control id — OCSF's mechanism for many framework ids.
	var checks []interface{}
	if controlID != "" {
		check := map[string]interface{}{"uid": controlID, "status_id": statusID}
		exportmap.SetIf(check, "name", title)
		if baselineName != "" {
			check["standards"] = []interface{}{baselineName}
		}
		checks = append(checks, check)
	}
	for _, id := range nist {
		checks = append(checks, map[string]interface{}{"uid": id, "standards": []interface{}{"NIST SP 800-53"}})
	}
	for _, id := range cci {
		checks = append(checks, map[string]interface{}{"uid": id, "standards": []interface{}{"CCI"}})
	}
	if len(checks) > 0 {
		compliance["checks"] = checks
	}
	return compliance
}

func buildVulnerabilities(cvssList []interface{}, req map[string]interface{}) []interface{} {
	cve := map[string]interface{}{}
	uid := exportmap.FirstCVE(cvssList)
	if uid == "" {
		uid = exportmap.GetStr(req, "id")
	}
	cve["uid"] = uid

	var cvssArr []interface{}
	for _, c := range cvssList {
		m, ok := exportmap.AsMap(c)
		if !ok {
			continue
		}
		entry := map[string]interface{}{}
		if bs, ok := m["baseScore"].(float64); ok {
			entry["base_score"] = exportmap.FloatToken(bs) // OCSF cvss.base_score is float_t
		}
		exportmap.SetIf(entry, "version", exportmap.GetStr(m, "version"))
		exportmap.SetIf(entry, "vector_string", exportmap.GetStr(m, "baseVector"))
		exportmap.SetIf(entry, "severity", exportmap.GetStr(m, "baseSeverity"))
		// Temporal/computed scoring: the environmental-adjusted score → cvss.
		// overall_score (float_t); the remaining temporal components → cvss.metrics[].
		if cs, ok := m["computedScore"].(float64); ok {
			entry["overall_score"] = exportmap.FloatToken(cs)
		}
		var metrics []interface{}
		if ts, ok := m["threatScore"].(float64); ok {
			metrics = append(metrics, map[string]interface{}{"name": "Threat Score", "value": floatMetric(ts)})
		}
		if tv := exportmap.GetStr(m, "threatVector"); tv != "" {
			metrics = append(metrics, map[string]interface{}{"name": "Threat Vector", "value": tv})
		}
		if cs := exportmap.GetStr(m, "computedSeverity"); cs != "" {
			metrics = append(metrics, map[string]interface{}{"name": "Computed Severity", "value": cs})
		}
		if len(metrics) > 0 {
			entry["metrics"] = metrics
		}
		cvssArr = append(cvssArr, entry)
	}
	if len(cvssArr) > 0 {
		cve["cvss"] = cvssArr
	}
	if cwes := exportmap.StringSlice(req["cwe"]); len(cwes) > 0 {
		var arr []interface{}
		for _, id := range cwes {
			arr = append(arr, map[string]interface{}{"uid": id})
		}
		cve["related_cwes"] = arr
	}

	vuln := map[string]interface{}{"cve": cve}
	exportmap.SetIf(vuln, "title", exportmap.GetStr(req, "title"))
	exportmap.SetIf(vuln, "desc", exportmap.DefaultDescription(req))
	if refs := allRefURLs(req); len(refs) > 0 {
		vuln["references"] = refs // ALL refs, not just the first
	}
	if rem := remediationText(req); rem != "" {
		vuln["remediation"] = map[string]interface{}{"desc": rem}
		vuln["fix_available"] = true
	}
	return []interface{}{vuln}
}

// labeledDescription returns the data of the first description carrying the given
// label, or "".
func labeledDescription(req map[string]interface{}, label string) string {
	descs, _ := exportmap.AsSlice(req["descriptions"])
	for _, dRaw := range descs {
		if d, ok := exportmap.AsMap(dRaw); ok && exportmap.GetStr(d, "label") == label {
			return exportmap.GetStr(d, "data")
		}
	}
	return ""
}

// remediationText returns the "fix"-labeled description as remediation guidance,
// treating a bare "n/a" placeholder as absent (no real remediation).
func remediationText(req map[string]interface{}) string {
	fix := labeledDescription(req, "fix")
	if strings.EqualFold(strings.TrimSpace(fix), "n/a") {
		return ""
	}
	return fix
}

// allRefURLs returns every non-empty refs[].url (not just the first).
func allRefURLs(req map[string]interface{}) []interface{} {
	refs, _ := exportmap.AsSlice(req["refs"])
	var out []interface{}
	for _, rRaw := range refs {
		if r, ok := exportmap.AsMap(rRaw); ok {
			if url := exportmap.GetStr(r, "url"); url != "" {
				out = append(out, url)
			}
		}
	}
	return out
}

// firstResultMessage returns results[0].message, or "".
func firstResultMessage(req map[string]interface{}) string {
	results, _ := exportmap.AsSlice(req["results"])
	if len(results) > 0 {
		if r, ok := exportmap.AsMap(results[0]); ok {
			return exportmap.GetStr(r, "message")
		}
	}
	return ""
}

// buildEvidences captures each result's codeDesc/message/status as an OCSF
// evidences[] artifact (its data object), preserving per-result check evidence
// that the scalar finding.message cannot hold.
func buildEvidences(req map[string]interface{}) []interface{} {
	results, _ := exportmap.AsSlice(req["results"])
	var out []interface{}
	for _, rRaw := range results {
		r, ok := exportmap.AsMap(rRaw)
		if !ok {
			continue
		}
		data := map[string]interface{}{}
		exportmap.SetIf(data, "code_desc", exportmap.GetStr(r, "codeDesc"))
		exportmap.SetIf(data, "message", exportmap.GetStr(r, "message"))
		exportmap.SetIf(data, "status", exportmap.GetStr(r, "status"))
		if len(data) > 0 {
			out = append(out, map[string]interface{}{"data": data})
		}
	}
	return out
}

// floatMetric renders a float as a plain decimal string for an OCSF Metric
// value (Metric.value is String). Go's shortest-decimal format and JS's String()
// agree over the low-precision decimals used here, keeping Go/TS byte-identical.
func floatMetric(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
