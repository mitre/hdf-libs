// Package hdftoecs exports HDF Results as Elastic Common Schema (ECS) NDJSON.
//
// One ECS event is emitted per Evaluated_Requirement, in the hybrid shape from
// ADR-0002: a core-ECS-native projection (event/rule/vulnerability/threat/
// observer/host/related.*) plus a lossless hdf.* block, with hot filter scalars
// promoted flat. Output is plain NDJSON (one object per line, LF-delimited,
// trailing newline), ECS 9.4.0.
//
// Status is effective-primary: event.outcome carries the GOVERNING verdict
// (effectiveStatus when present, else the raw results roll-up), while hdf.status
// preserves the RAW verdict and hdf.suppressed is the separate acceptance axis.
// Override provenance (disposition, override type, reason, approver, dates) is
// surfaced under labels.*. The canonical "still actionable" consumer query is
// event.outcome:"failure" AND hdf.suppressed:false.
//
// Generic JSON access, the status roll-up, requirement/document field
// extraction, and the canonical line encoder are shared with the other export
// converters via the exportmap package; only ECS-specific event shaping lives
// here. To guarantee byte-identical output with the TypeScript implementation,
// the converter operates on generically-parsed JSON and emits alphabetically
// key-sorted, HTML-unescaped compact JSON; timestamps pass through as raw
// source strings.
package hdftoecs

import (
	"math"
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
)

const ecsVersion = "9.4.0"

// ConvertHDFToECS converts an HDF Results document to ECS NDJSON.
func ConvertHDFToECS(input []byte, converterVersion string) ([]byte, error) {
	return exportmap.Export(input, "hdf-to-ecs",
		func(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}) map[string]interface{} {
			return buildEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion)
		})
}

// buildEvent maps one Evaluated_Requirement to a single ECS event object.
func buildEvent(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}, converterVersion string) map[string]interface{} {
	st := exportmap.StatusOf(req)
	outcome := statusToOutcome(st.Rollup)
	controlID := exportmap.GetStr(req, "id")
	baselineName := exportmap.GetStr(baseline, "name")
	title := exportmap.GetStr(req, "title")

	cvssList, hasCVSS := exportmap.AsSlice(req["cvss"])
	hasCVSS = hasCVSS && len(cvssList) > 0

	// event.*
	categories := []interface{}{"configuration"}
	if hasCVSS {
		categories = append(categories, "vulnerability")
	}
	event := map[string]interface{}{
		"kind":     "state",
		"category": categories,
		"type":     []interface{}{"info"},
		"outcome":  outcome,
		"id":       exportmap.EventID(component, baselineName, controlID),
		"dataset":  "hdf.findings",
		"module":   "hdf",
	}
	// event.start / event.duration from per-result timing (results[0]).
	if start := firstRawStartTime(req); start != "" {
		event["start"] = start
	}
	if rt, ok := firstRunTime(req); ok {
		event["duration"] = int64(math.Round(rt * 1e9)) // ECS event.duration is nanoseconds
	}

	obj := map[string]interface{}{
		"@timestamp": exportmap.FirstResultStartTime(req, docTimestamp),
		"ecs":        map[string]interface{}{"version": ecsVersion},
		"event":      event,
		"message":    strings.TrimSpace(title + " — " + st.Raw),
	}

	// observer.* (tool, fallback generator)
	if observer := buildObserver(tool, generator); observer != nil {
		obj["observer"] = observer
	}
	// host.* / related.*
	if host := buildHost(component); host != nil {
		obj["host"] = host
		if related := buildRelated(component); related != nil {
			obj["related"] = related
		}
	}
	// rule.*
	obj["rule"] = buildRule(req, baseline, controlID, title)
	// vulnerability.* (only when CVE data present)
	if hasCVSS {
		obj["vulnerability"] = buildVulnerability(cvssList, req, tool)
	}
	// threat.* (ATT&CK from tags, best-effort)
	if threat := buildThreat(req); threat != nil {
		obj["threat"] = threat
	}
	// log.origin.file.* from the requirement's source location (control file/line).
	if sl, ok := exportmap.AsMap(req["sourceLocation"]); ok {
		file := map[string]interface{}{}
		exportmap.SetIf(file, "name", exportmap.GetStr(sl, "ref"))
		if line, ok := sl["line"]; ok {
			file["line"] = line
		}
		if len(file) > 0 {
			obj["log"] = map[string]interface{}{"origin": map[string]interface{}{"file": file}}
		}
	}
	// labels.* — override provenance (disposition/type/reason/approver/dates).
	if labels := buildLabels(req); labels != nil {
		obj["labels"] = labels
	}
	// hdf.* lossless block, plus the requirement/baseline fields the shared
	// allowlist omits (control classification, verification method, baseline
	// title and integrity checksum) so the block stays genuinely lossless.
	hdf := exportmap.BuildHDFBlock(req, baseline, st.Raw, st.Overridden, st.Suppressed, generator, tool, converterVersion)
	if v, ok := req["controlType"]; ok {
		hdf["control_type"] = v
	}
	if v, ok := req["verificationMethod"]; ok {
		hdf["verification_method"] = v
	}
	if v, ok := baseline["title"]; ok {
		hdf["baseline_title"] = v
	}
	if v, ok := baseline["checksum"]; ok {
		hdf["baseline_checksum"] = v
	}
	obj["hdf"] = hdf

	return obj
}

// buildLabels surfaces override provenance into ECS labels.* (keyword bag): the
// disposition plus the governing statusOverrides[0] fields. Returns nil when the
// requirement carries no disposition or overrides.
func buildLabels(req map[string]interface{}) map[string]interface{} {
	labels := map[string]interface{}{}
	exportmap.SetIf(labels, "hdf_disposition", exportmap.GetStr(req, "disposition"))
	if overrides, ok := exportmap.AsSlice(req["statusOverrides"]); ok && len(overrides) > 0 {
		if ov, ok := exportmap.AsMap(overrides[0]); ok {
			exportmap.SetIf(labels, "hdf_override_type", exportmap.GetStr(ov, "type"))
			exportmap.SetIf(labels, "hdf_override_reason", exportmap.GetStr(ov, "reason"))
			if by, ok := exportmap.AsMap(ov["appliedBy"]); ok {
				exportmap.SetIf(labels, "hdf_override_applied_by", exportmap.GetStr(by, "identifier"))
			}
			exportmap.SetIf(labels, "hdf_override_applied_at", exportmap.GetStr(ov, "appliedAt"))
			exportmap.SetIf(labels, "hdf_override_expires_at", exportmap.GetStr(ov, "expiresAt"))
		}
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

// firstRawStartTime returns results[0].startTime with no fallback, or "".
func firstRawStartTime(req map[string]interface{}) string {
	if results, ok := exportmap.AsSlice(req["results"]); ok && len(results) > 0 {
		if r, ok := exportmap.AsMap(results[0]); ok {
			return exportmap.GetStr(r, "startTime")
		}
	}
	return ""
}

// firstRunTime returns results[0].runTime (seconds), or (0,false) when absent.
func firstRunTime(req map[string]interface{}) (float64, bool) {
	if results, ok := exportmap.AsSlice(req["results"]); ok && len(results) > 0 {
		if r, ok := exportmap.AsMap(results[0]); ok {
			if rt, ok := r["runTime"].(float64); ok {
				return rt, true
			}
		}
	}
	return 0, false
}

// allRefURLs returns every non-empty refs[].url, preserving order.
func allRefURLs(req map[string]interface{}) []interface{} {
	refs, _ := exportmap.AsSlice(req["refs"])
	var urls []interface{}
	for _, rRaw := range refs {
		if r, ok := exportmap.AsMap(rRaw); ok {
			if url := exportmap.GetStr(r, "url"); url != "" {
				urls = append(urls, url)
			}
		}
	}
	return urls
}

func buildObserver(tool, generator map[string]interface{}) map[string]interface{} {
	name := exportmap.GetStr(tool, "name")
	version := exportmap.GetStr(tool, "version")
	if name == "" && generator != nil {
		name = exportmap.GetStr(generator, "name")
		version = exportmap.GetStr(generator, "version")
	}
	if name == "" {
		return nil
	}
	observer := map[string]interface{}{"name": name, "type": "scanner"}
	if version != "" {
		observer["version"] = version
	}
	if product := exportmap.GetStr(tool, "format"); product != "" {
		observer["product"] = product
	}
	return observer
}

func buildHost(component map[string]interface{}) map[string]interface{} {
	if component == nil {
		return nil
	}
	host := map[string]interface{}{}
	name := exportmap.GetStr(component, "fqdn")
	if name == "" {
		name = exportmap.GetStr(component, "name")
	}
	if name != "" {
		host["name"] = name
	}
	exportmap.SetIf(host, "id", exportmap.GetStr(component, "componentId"))
	exportmap.SetIf(host, "ip", exportmap.GetStr(component, "ipAddress"))
	exportmap.SetIf(host, "mac", exportmap.GetStr(component, "macAddress"))
	os := map[string]interface{}{}
	exportmap.SetIf(os, "name", exportmap.GetStr(component, "osName"))
	exportmap.SetIf(os, "version", exportmap.GetStr(component, "osVersion"))
	if len(os) > 0 {
		host["os"] = os
	}
	if len(host) == 0 {
		return nil
	}
	return host
}

func buildRelated(component map[string]interface{}) map[string]interface{} {
	related := map[string]interface{}{}
	name := exportmap.GetStr(component, "fqdn")
	if name == "" {
		name = exportmap.GetStr(component, "name")
	}
	if name != "" {
		related["hosts"] = []interface{}{name}
	}
	if ip := exportmap.GetStr(component, "ipAddress"); ip != "" {
		related["ip"] = []interface{}{ip}
	}
	if len(related) == 0 {
		return nil
	}
	return related
}

func buildRule(req, baseline map[string]interface{}, controlID, title string) map[string]interface{} {
	rule := map[string]interface{}{"id": controlID}
	if title != "" {
		rule["name"] = title
	}
	exportmap.SetIf(rule, "description", exportmap.DefaultDescription(req))
	exportmap.SetIf(rule, "ruleset", exportmap.GetStr(baseline, "name"))
	exportmap.SetIf(rule, "version", exportmap.GetStr(baseline, "version"))
	if urls := allRefURLs(req); len(urls) > 0 {
		rule["reference"] = urls
	}
	return rule
}

func buildVulnerability(cvssList []interface{}, req, tool map[string]interface{}) map[string]interface{} {
	first, _ := exportmap.AsMap(cvssList[0])
	vuln := map[string]interface{}{}
	source := exportmap.GetStr(first, "source")
	if source != "" {
		vuln["id"] = source
		if strings.HasPrefix(strings.ToUpper(source), "CVE-") {
			vuln["enumeration"] = "CVE"
		}
	} else if id := exportmap.GetStr(req, "id"); id != "" {
		vuln["id"] = id
	}
	version := exportmap.GetStr(first, "version")
	if version != "" {
		vuln["classification"] = "CVSS v" + version // derived from the real cvss[] scoring version
	} else {
		vuln["classification"] = "CVSS"
	}
	score := map[string]interface{}{}
	if base, ok := first["baseScore"]; ok {
		score["base"] = base
	}
	if version != "" {
		score["version"] = version
	}
	if len(score) > 0 {
		vuln["score"] = score
	}
	severity := exportmap.GetStr(first, "baseSeverity")
	if severity == "" {
		severity = exportmap.GetStr(req, "severity")
	}
	if severity != "" {
		vuln["severity"] = severity
	}
	if vendor := exportmap.GetStr(tool, "name"); vendor != "" {
		vuln["scanner"] = map[string]interface{}{"vendor": vendor}
	}
	if urls := allRefURLs(req); len(urls) > 0 {
		vuln["reference"] = urls
	}
	exportmap.SetIf(vuln, "description", exportmap.DefaultDescription(req))
	return vuln
}

// buildThreat projects ATT&CK technique ids from tags to core threat.*.
func buildThreat(req map[string]interface{}) map[string]interface{} {
	tags, ok := exportmap.AsMap(req["tags"])
	if !ok {
		return nil
	}
	var techniques []interface{}
	for _, key := range []string{"mitre_attack", "attack", "mitre_techniques"} {
		vals := exportmap.StringSlice(tags[key])
		for _, id := range vals {
			techniques = append(techniques, map[string]interface{}{"id": id})
		}
	}
	if len(techniques) == 0 {
		return nil
	}
	return map[string]interface{}{
		"framework": "MITRE ATT&CK",
		"technique": techniques,
	}
}

// statusToOutcome maps an HDF Result_Status to an ECS event.outcome.
func statusToOutcome(status string) string {
	switch status {
	case "passed":
		return "success"
	case "failed":
		return "failure"
	default: // notApplicable, notReviewed, error
		return "unknown"
	}
}
