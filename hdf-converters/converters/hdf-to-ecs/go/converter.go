// Package hdftoecs exports HDF Results as Elastic Common Schema (ECS) NDJSON.
//
// One ECS event is emitted per Evaluated_Requirement, in the hybrid shape from
// ADR-0002: a core-ECS-native projection (event/rule/vulnerability/threat/
// observer/host/related.*) plus a lossless hdf.* block, with hot filter scalars
// promoted flat. Output is plain NDJSON (one object per line, LF-delimited,
// trailing newline), ECS 9.4.0.
//
// Status is raw-primary: event.outcome carries the RAW verdict (a waived failure
// is still failure), and hdf.suppressed is the separate acceptance axis. The
// canonical "still actionable" consumer query is
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
	outcome := statusToOutcome(st.Raw)
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
	// hdf.* lossless block
	obj["hdf"] = exportmap.BuildHDFBlock(req, baseline, st.Raw, st.Overridden, st.Suppressed, generator, tool, converterVersion)

	return obj
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
	exportmap.SetIf(rule, "reference", exportmap.FirstRefURL(req))
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
	vuln["classification"] = "CVSS"
	score := map[string]interface{}{}
	if base, ok := first["baseScore"]; ok {
		score["base"] = base
	}
	if version := exportmap.GetStr(first, "version"); version != "" {
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
