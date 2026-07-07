// Package hdftoecs exports HDF Results as Elastic Common Schema (ECS) NDJSON.
//
// One ECS event is emitted per Evaluated_Requirement, in the hybrid shape from
// ADR-0002: a core-ECS-native projection (event/rule/vulnerability/threat/
// observer/host/related.*) plus a lossless hdf.* block, with hot filter scalars
// promoted flat. Output is plain NDJSON (one object per line, LF-delimited,
// trailing newline), ECS 9.4.0.
//
// To guarantee byte-identical output with the TypeScript implementation, the
// converter operates on generically-parsed JSON and emits alphabetically
// key-sorted, HTML-unescaped compact JSON; timestamps pass through as raw
// source strings.
package hdftoecs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
)

const ecsVersion = "9.4.0"

// ConvertHDFToECS converts an HDF Results document to ECS NDJSON.
func ConvertHDFToECS(input []byte, converterVersion string) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-ecs: empty input")
	}
	if err := shared.ValidateJSONSize(input, "hdf-to-ecs", 0); err != nil {
		return nil, fmt.Errorf("hdf-to-ecs: %w", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("hdf-to-ecs: invalid HDF JSON: %w", err)
	}
	baselines, ok := asSlice(doc["baselines"])
	if !ok {
		return nil, fmt.Errorf("hdf-to-ecs: invalid HDF structure: missing baselines field")
	}

	docTimestamp := getStr(doc, "timestamp")
	tool, _ := asMap(doc["tool"])
	generator, _ := asMap(doc["generator"])
	component := firstComponent(doc)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	for _, bRaw := range baselines {
		baseline, ok := asMap(bRaw)
		if !ok {
			continue
		}
		reqs, _ := asSlice(baseline["requirements"])
		for _, rRaw := range reqs {
			req, ok := asMap(rRaw)
			if !ok {
				continue
			}
			event := buildEvent(req, baseline, docTimestamp, tool, generator, component, converterVersion)
			if err := enc.Encode(event); err != nil {
				return nil, fmt.Errorf("hdf-to-ecs: encode: %w", err)
			}
		}
	}

	return buf.Bytes(), nil
}

// buildEvent maps one Evaluated_Requirement to a single ECS event object.
func buildEvent(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}, converterVersion string) map[string]interface{} {
	rawStatus := worstOfResults(req)            // lossless status from results[]
	effStatus := getStr(req, "effectiveStatus") // set only when overridden
	rollup := effStatus
	if rollup == "" {
		rollup = rawStatus
	}
	outcome := statusToOutcome(rollup)
	controlID := getStr(req, "id")
	baselineName := getStr(baseline, "name")
	title := getStr(req, "title")

	cvssList, hasCVSS := asSlice(req["cvss"])
	overrides, _ := asSlice(req["statusOverrides"])
	_, hasEffective := req["effectiveStatus"]
	overridden := len(overrides) > 0 || hasEffective

	// event.*
	categories := []interface{}{"configuration"}
	if hasCVSS && len(cvssList) > 0 {
		categories = append(categories, "vulnerability")
	}
	event := map[string]interface{}{
		"kind":     "state",
		"category": categories,
		"type":     []interface{}{"info"},
		"outcome":  outcome,
		"id":       eventID(component, baselineName, controlID),
		"dataset":  "hdf.findings",
		"module":   "hdf",
	}

	obj := map[string]interface{}{
		"@timestamp": firstResultStartTime(req, docTimestamp),
		"ecs":        map[string]interface{}{"version": ecsVersion},
		"event":      event,
		"message":    strings.TrimSpace(title + " — " + rollup),
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
	if hasCVSS && len(cvssList) > 0 {
		obj["vulnerability"] = buildVulnerability(cvssList, req, tool)
	}
	// threat.* (ATT&CK from tags, best-effort)
	if threat := buildThreat(req); threat != nil {
		obj["threat"] = threat
	}
	// hdf.* lossless block
	obj["hdf"] = buildHDFBlock(req, baseline, rawStatus, overridden, generator, tool, converterVersion)

	return obj
}

func buildObserver(tool, generator map[string]interface{}) map[string]interface{} {
	name := getStr(tool, "name")
	version := getStr(tool, "version")
	if name == "" && generator != nil {
		name = getStr(generator, "name")
		version = getStr(generator, "version")
	}
	if name == "" {
		return nil
	}
	observer := map[string]interface{}{"name": name, "type": "scanner"}
	if version != "" {
		observer["version"] = version
	}
	if product := getStr(tool, "format"); product != "" {
		observer["product"] = product
	}
	return observer
}

func buildHost(component map[string]interface{}) map[string]interface{} {
	if component == nil {
		return nil
	}
	host := map[string]interface{}{}
	name := getStr(component, "fqdn")
	if name == "" {
		name = getStr(component, "name")
	}
	if name != "" {
		host["name"] = name
	}
	if id := getStr(component, "componentId"); id != "" {
		host["id"] = id
	}
	if ip := getStr(component, "ipAddress"); ip != "" {
		host["ip"] = ip
	}
	if mac := getStr(component, "macAddress"); mac != "" {
		host["mac"] = mac
	}
	os := map[string]interface{}{}
	if osName := getStr(component, "osName"); osName != "" {
		os["name"] = osName
	}
	if osVersion := getStr(component, "osVersion"); osVersion != "" {
		os["version"] = osVersion
	}
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
	name := getStr(component, "fqdn")
	if name == "" {
		name = getStr(component, "name")
	}
	if name != "" {
		related["hosts"] = []interface{}{name}
	}
	if ip := getStr(component, "ipAddress"); ip != "" {
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
	if desc := defaultDescription(req); desc != "" {
		rule["description"] = desc
	}
	if name := getStr(baseline, "name"); name != "" {
		rule["ruleset"] = name
	}
	if version := getStr(baseline, "version"); version != "" {
		rule["version"] = version
	}
	if ref := firstRefURL(req); ref != "" {
		rule["reference"] = ref
	}
	return rule
}

func buildVulnerability(cvssList []interface{}, req, tool map[string]interface{}) map[string]interface{} {
	first, _ := asMap(cvssList[0])
	vuln := map[string]interface{}{}
	source := getStr(first, "source")
	if source != "" {
		vuln["id"] = source
		if strings.HasPrefix(strings.ToUpper(source), "CVE-") {
			vuln["enumeration"] = "CVE"
		}
	} else if id := getStr(req, "id"); id != "" {
		vuln["id"] = id
	}
	vuln["classification"] = "CVSS"
	score := map[string]interface{}{}
	if base, ok := first["baseScore"]; ok {
		score["base"] = base
	}
	if version := getStr(first, "version"); version != "" {
		score["version"] = version
	}
	if len(score) > 0 {
		vuln["score"] = score
	}
	severity := getStr(first, "baseSeverity")
	if severity == "" {
		severity = getStr(req, "severity")
	}
	if severity != "" {
		vuln["severity"] = severity
	}
	if vendor := getStr(tool, "name"); vendor != "" {
		vuln["scanner"] = map[string]interface{}{"vendor": vendor}
	}
	if desc := defaultDescription(req); desc != "" {
		vuln["description"] = desc
	}
	return vuln
}

// buildThreat projects ATT&CK technique ids from tags to core threat.*.
func buildThreat(req map[string]interface{}) map[string]interface{} {
	tags, ok := asMap(req["tags"])
	if !ok {
		return nil
	}
	var techniques []interface{}
	for _, key := range []string{"mitre_attack", "attack", "mitre_techniques"} {
		vals := stringSlice(tags[key])
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

// buildHDFBlock is the lossless hdf.* namespace: promoted scalars (snake_case)
// plus the full requirement sub-objects preserved verbatim.
func buildHDFBlock(req, baseline map[string]interface{}, status string, overridden bool, generator, tool map[string]interface{}, converterVersion string) map[string]interface{} {
	hdf := map[string]interface{}{
		"status":           status,
		"overridden":       overridden,
		"exporter_version": converterVersion,
	}
	setIf(hdf, "control_id", getStr(req, "id"))
	setIf(hdf, "baseline", getStr(baseline, "name"))
	if v, ok := req["effectiveStatus"]; ok {
		hdf["effective_status"] = v
	}
	if v, ok := req["effectiveImpact"]; ok {
		hdf["effective_impact"] = v
	}
	if v, ok := req["impact"]; ok {
		hdf["impact"] = v
	}
	if v, ok := req["severity"]; ok {
		hdf["severity"] = v
	}
	if v, ok := req["disposition"]; ok {
		hdf["disposition"] = v
	}
	tags, _ := asMap(req["tags"])
	if nist := tags["nist"]; nist != nil {
		hdf["nist"] = nist
	}
	if cci := tags["cci"]; cci != nil {
		hdf["cci"] = cci
	}
	// lossless passthrough sub-objects
	passthrough := map[string]string{
		"tags":             "tags",
		"cvss":             "cvss",
		"cwe":              "cwe",
		"epss":             "epss",
		"kev":              "kev",
		"affectedPackages": "affected_packages",
		"descriptions":     "descriptions",
		"results":          "results",
		"statusOverrides":  "status_overrides",
		"poams":            "poams",
		"code":             "code",
		"refs":             "refs",
	}
	for src, dst := range passthrough {
		if v, ok := req[src]; ok {
			hdf[dst] = v
		}
	}
	if generator != nil {
		hdf["generator"] = generator
	}
	if tool != nil {
		hdf["tool"] = tool
	}
	return hdf
}

// worstOfResults returns the most-significant status across the requirement's
// results[] (lossless — does not consult effectiveStatus).
func worstOfResults(req map[string]interface{}) string {
	results, _ := asSlice(req["results"])
	// precedence worst→best: failed, error, passed, notReviewed, notApplicable
	precedence := []string{"failed", "error", "passed", "notReviewed", "notApplicable"}
	present := map[string]bool{}
	for _, rRaw := range results {
		if r, ok := asMap(rRaw); ok {
			present[getStr(r, "status")] = true
		}
	}
	for _, s := range precedence {
		if present[s] {
			return s
		}
	}
	return "notReviewed"
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

func eventID(component map[string]interface{}, baselineName, controlID string) string {
	comp := ""
	if component != nil {
		comp = getStr(component, "componentId")
		if comp == "" {
			comp = getStr(component, "name")
		}
	}
	return strings.Join([]string{comp, baselineName, controlID}, "|")
}

func firstComponent(doc map[string]interface{}) map[string]interface{} {
	comps, ok := asSlice(doc["components"])
	if !ok || len(comps) == 0 {
		return nil
	}
	c, _ := asMap(comps[0])
	return c
}

func firstResultStartTime(req map[string]interface{}, fallback string) string {
	results, _ := asSlice(req["results"])
	if len(results) > 0 {
		if r, ok := asMap(results[0]); ok {
			if st := getStr(r, "startTime"); st != "" {
				return st
			}
		}
	}
	return fallback
}

func defaultDescription(req map[string]interface{}) string {
	descs, _ := asSlice(req["descriptions"])
	for _, dRaw := range descs {
		if d, ok := asMap(dRaw); ok && getStr(d, "label") == "default" {
			return getStr(d, "data")
		}
	}
	return ""
}

func firstRefURL(req map[string]interface{}) string {
	refs, _ := asSlice(req["refs"])
	for _, rRaw := range refs {
		if r, ok := asMap(rRaw); ok {
			if url := getStr(r, "url"); url != "" {
				return url
			}
		}
	}
	return ""
}

// --- generic-access helpers ---

func asMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

func asSlice(v interface{}) ([]interface{}, bool) {
	s, ok := v.([]interface{})
	return s, ok
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func setIf(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func stringSlice(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
