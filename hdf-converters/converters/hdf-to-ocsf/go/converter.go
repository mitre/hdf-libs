// Package hdftoocsf exports HDF Results as OCSF (Open Cybersecurity Schema
// Framework) Finding NDJSON, per the ADR-0002 addendum (HDF → OCSF, wvc3.5).
//
// One OCSF Finding is emitted per Evaluated_Requirement: a CVE finding →
// Vulnerability Finding (class_uid 2002), any other → Compliance Finding
// (class_uid 2003), both under the Findings category (2). Pinned to OCSF v1.8.0.
//
// Status model (raw-primary): compliance.status_id carries the RAW verdict
// (Pass/Warning/Fail) — a failed control stays Fail even when waived, so a
// consumer never mistakes a waiver for a pass. HDF overrides ride the base
// finding status_id (New vs Suppressed), the "is it still my problem?" axis;
// the exact override type/justification/chain is preserved losslessly in
// unmapped.hdf_requirement (+ a human comment). See the ADR addendum's
// "Override representation" for the canonical consumer query.
//
// Generic JSON access, the status roll-up, field extraction, and the canonical
// byte-identical line encoder are shared with the other exporters via exportmap;
// only OCSF-specific shaping lives here.
package hdftoocsf

import (
	"encoding/json"
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
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
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-ocsf: empty input")
	}
	if err := shared.ValidateJSONSize(input, "hdf-to-ocsf", 0); err != nil {
		return nil, fmt.Errorf("hdf-to-ocsf: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("hdf-to-ocsf: invalid HDF JSON: %w", err)
	}
	baselines, ok := exportmap.AsSlice(doc["baselines"])
	if !ok {
		return nil, fmt.Errorf("hdf-to-ocsf: invalid HDF structure: missing baselines field")
	}

	docTimestamp := exportmap.GetStr(doc, "timestamp")
	tool, _ := exportmap.AsMap(doc["tool"])
	generator, _ := exportmap.AsMap(doc["generator"])
	component := exportmap.FirstComponent(doc)

	var out []byte
	for _, bRaw := range baselines {
		baseline, ok := exportmap.AsMap(bRaw)
		if !ok {
			continue
		}
		reqs, _ := exportmap.AsSlice(baseline["requirements"])
		for _, rRaw := range reqs {
			req, ok := exportmap.AsMap(rRaw)
			if !ok {
				continue
			}
			finding := buildFinding(req, baseline, docTimestamp, tool, generator, component)
			line, err := exportmap.EncodeLine(finding)
			if err != nil {
				return nil, fmt.Errorf("hdf-to-ocsf: encode: %w", err)
			}
			out = append(out, line...)
		}
	}
	return out, nil
}

// buildFinding maps one Evaluated_Requirement to a single OCSF Finding object.
func buildFinding(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}) map[string]interface{} {
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

	finding := map[string]interface{}{
		"category_uid": categoryFindings,
		"class_uid":    class,
		"type_uid":     class*100 + activityCreate,
		"activity_id":  activityCreate,
		"severity_id":  severityID(req),
		"status_id":    overrideStatusID(st),
		"metadata":     buildMetadata(tool, generator),
		"finding_info": findingInfo,
		"unmapped":     map[string]interface{}{"hdf_requirement": req},
	}
	if ms, ok := epochMillis(exportmap.FirstResultStartTime(req, docTimestamp)); ok {
		finding["time"] = ms
	}
	exportmap.SetIf(finding, "comment", overrideComment(req))
	if device := buildDevice(component); device != nil {
		finding["device"] = device
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
		switch {
		case impact >= 0.9:
			return 5
		case impact >= 0.7:
			return 4
		case impact >= 0.4:
			return 3
		case impact >= 0.1:
			return 2
		default:
			return 1
		}
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
// the exact HDF status is preserved verbatim in compliance.status + unmapped.
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

// overrideStatusID encodes HDF override state onto the base finding status_id:
// any active override → 3 Suppressed (adjudicated), else 1 New (actionable).
func overrideStatusID(st exportmap.Status) int {
	if st.Overridden {
		return statusSuppressed
	}
	return statusNew
}

func overrideComment(req map[string]interface{}) string {
	disposition := exportmap.GetStr(req, "disposition")
	overrides, _ := exportmap.AsSlice(req["statusOverrides"])
	if disposition == "" && len(overrides) == 0 {
		return ""
	}
	justification := ""
	if len(overrides) > 0 {
		if first, ok := exportmap.AsMap(overrides[0]); ok {
			justification = exportmap.GetStr(first, "justification")
		}
	}
	switch {
	case disposition != "" && justification != "":
		return disposition + ": " + justification
	case disposition != "":
		return disposition
	default:
		return justification
	}
}

func buildMetadata(tool, generator map[string]interface{}) map[string]interface{} {
	metadata := map[string]interface{}{"version": ocsfVersion}
	name := exportmap.GetStr(tool, "name")
	version := exportmap.GetStr(tool, "version")
	if name == "" && generator != nil {
		name = exportmap.GetStr(generator, "name")
		version = exportmap.GetStr(generator, "version")
	}
	if name != "" {
		product := map[string]interface{}{"name": name}
		exportmap.SetIf(product, "version", version)
		exportmap.SetIf(product, "vendor_name", exportmap.GetStr(tool, "format"))
		metadata["product"] = product
	}
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

func buildCompliance(req, baseline map[string]interface{}, title, rawStatus string) map[string]interface{} {
	statusID := complianceStatusID(rawStatus)
	compliance := map[string]interface{}{
		"status_id": statusID,
		"status":    rawStatus, // verbatim HDF status
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
	uid := firstCVE(cvssList)
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
			entry["base_score"] = bs
		}
		exportmap.SetIf(entry, "version", exportmap.GetStr(m, "version"))
		exportmap.SetIf(entry, "vector_string", exportmap.GetStr(m, "baseVector"))
		exportmap.SetIf(entry, "severity", exportmap.GetStr(m, "baseSeverity"))
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
	if ref := exportmap.FirstRefURL(req); ref != "" {
		vuln["references"] = []interface{}{ref}
	}
	return []interface{}{vuln}
}

// firstCVE returns the first CVE-shaped cvss[].source, or "".
func firstCVE(cvssList []interface{}) string {
	for _, c := range cvssList {
		if m, ok := exportmap.AsMap(c); ok {
			if src := exportmap.GetStr(m, "source"); strings.HasPrefix(strings.ToUpper(src), "CVE-") {
				return src
			}
		}
	}
	return ""
}

// epochMillis parses an HDF RFC3339 timestamp into integer epoch milliseconds
// (OCSF's `time` convention) via the canonical parser, returning (0,false) when
// empty/unparseable. Integer millis keep Go and TypeScript byte-identical.
func epochMillis(s string) (int64, bool) {
	t := hdfutil.ParseTimestamp(s)
	if t.IsZero() {
		return 0, false
	}
	return t.UnixMilli(), true
}
