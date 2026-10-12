// Package hdftosarif converts HDF Results to a SARIF 2.1.0 static-analysis log.
//
// This is the reverse direction of sarif-to-hdf. It works on generically-parsed
// JSON rather than the typed HDF structs so the output stays byte-identical with
// the TypeScript peer: SARIF property bags are open maps, and Go sorts map keys
// while JSON.stringify preserves insertion order, so both languages canonicalize
// the whole document instead of maintaining two field orders by hand.
package hdftosarif

import (
	"sort"
	"strconv"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/exportmap"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	converterName = "hdf-to-sarif"

	// SARIFVersion is the only value the 2.1.0 schema's version enum admits.
	SARIFVersion = "2.1.0"

	// SARIFSchemaURI is the OASIS canonical location of the schema this output
	// is validated against (vendored at sarif-to-hdf/fixtures/).
	SARIFSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

	// unnamedTool fills run.tool.driver.name, which SARIF requires, when the HDF
	// document names neither a tool nor a generator. The same documented constant
	// hdf-to-oscal-sar uses for the same gap; inventing a plausible tool name
	// would be fabrication.
	unnamedTool = "HDF Assessment Tool"

	// hdfBagKey is the single reserved property-bag key under which HDF data that
	// SARIF has no field for is carried. One key rather than many prefixed ones
	// keeps the collision surface minimal and groups the block for a consumer.
	hdfBagKey = "hdf"

	// regionTag is the requirement tag carrying SARIF region precision
	// (startColumn/endLine/endColumn/offsets/snippet). HDF's Source_Location is
	// {ref, line} and closed, so the rest of a region lives in this documented
	// tag convention rather than in a schema field.
	regionTag = "sarif-region"
)

// ConvertHDFToSARIF converts HDF Results JSON bytes to a SARIF 2.1.0 log.
func ConvertHDFToSARIF(input []byte, converterVersion string) ([]byte, error) {
	doc, baselines, err := shared.RequireHDFResults(input, converterName)
	if err != nil {
		return nil, err
	}
	return exportmap.EncodeDocument(buildLog(doc, baselines, converterVersion))
}

// buildLog assembles the whole SARIF log: one run per baseline.
func buildLog(doc map[string]interface{}, baselines []interface{}, converterVersion string) map[string]interface{} {
	carried := readCarriedBags(doc)
	generator, _ := exportmap.AsMap(doc["generator"])
	tool, _ := exportmap.AsMap(doc["tool"])

	runs := make([]interface{}, 0, len(baselines))
	for _, raw := range baselines {
		baseline, ok := exportmap.AsMap(raw)
		if !ok {
			continue
		}
		runs = append(runs, buildRun(baseline, generator, tool, converterVersion, carried))
	}

	log := map[string]interface{}{
		"$schema": SARIFSchemaURI,
		"version": SARIFVersion,
		"runs":    runs,
	}
	setBag(log, documentBlock(doc), carried.find(address{On: onLog}))
	return log
}

// documentBlock is the document-level HDF data SARIF has no field for. The
// mapped fields (tool, generator) are deliberately absent: tool reaches
// run.tool.driver and generator reaches run.properties, so repeating them here
// would be dumping data that already has a home.
func documentBlock(doc map[string]interface{}) map[string]interface{} {
	block := map[string]interface{}{}
	for _, key := range []string{
		"id", "timestamp", "statistics", "runner", "components", "planRef",
		"systemRef", "integrity", "externalReferences", "derivation",
		"preAmendmentChecksum", "remediation",
	} {
		if v, ok := doc[key]; ok {
			block[key] = v
		}
	}
	if ext := remainingExtensions(doc); len(ext) > 0 {
		block["extensions"] = ext
	}
	if len(block) == 0 {
		return nil
	}
	return map[string]interface{}{hdfBagKey: block}
}

// buildRun maps one HDF baseline onto one SARIF run.
//
// One run per baseline, not one per document: SARIF ties a run to a single tool
// invocation, and the baseline is the HDF unit that carries its own identity
// (name, version, checksums, status). Flattening several baselines into one run
// would lose all of it and merge rules that were never evaluated together.
func buildRun(
	baseline, generator, tool map[string]interface{},
	converterVersion string,
	carried carriedBags,
) map[string]interface{} {
	baselineName := exportmap.GetStr(baseline, "name")
	rules, results := buildRulesAndResults(baseline, baselineName, generator, tool, converterVersion, carried)

	driver := map[string]interface{}{"name": driverName(tool)}
	exportmap.SetIf(driver, "version", exportmap.GetStr(tool, "version"))
	exportmap.SetIf(driver, "informationUri", AbsoluteURI(exportmap.GetStr(tool, "url")))
	if len(rules) > 0 {
		driver["rules"] = rules
	}
	setBag(driver, nil, carried.find(address{On: onDriver, Baseline: baselineName}))

	run := map[string]interface{}{"tool": map[string]interface{}{"driver": driver}}
	if len(results) > 0 {
		run["results"] = results
	}
	// SARIF's conversion object describes the converter that produced this log,
	// which is this exporter; the HDF generator converted some earlier format
	// into HDF and SARIF models no chain of them, so it stays in the run's bag.
	conversion := map[string]interface{}{
		"tool": map[string]interface{}{
			"driver": map[string]interface{}{"name": converterName, "version": converterVersion},
		},
	}
	setBag(conversion, nil, carried.find(address{On: onConversion, Baseline: baselineName}))
	run["conversion"] = conversion
	if details := automationDetails(baseline, baselineName); details != nil {
		run["automationDetails"] = details
	}
	setBag(run, baselineBlock(baseline, generator), carried.find(address{On: onRun, Baseline: baselineName}))
	return run
}

// driverName resolves run.tool.driver.name, which SARIF requires.
func driverName(tool map[string]interface{}) string {
	if name := exportmap.GetStr(tool, "name"); name != "" {
		return name
	}
	return unnamedTool
}

// automationDetails carries the baseline's identity: runAutomationDetails.id is
// SARIF's "hierarchical string that uniquely identifies this run", which is
// exactly what an HDF baseline name is within a document.
func automationDetails(baseline map[string]interface{}, baselineName string) map[string]interface{} {
	if baselineName == "" {
		return nil
	}
	details := map[string]interface{}{"id": baselineName}
	if text := exportmap.GetStr(baseline, "title"); text != "" {
		details["description"] = map[string]interface{}{"text": text}
	}
	return details
}

// baselineBlock is the baseline's own HDF data with no SARIF field, plus the
// document generator (an upstream converter SARIF cannot represent).
func baselineBlock(baseline, generator map[string]interface{}) map[string]interface{} {
	block := map[string]interface{}{}
	for _, key := range []string{
		"name", "title", "version", "summary", "description", "maintainer",
		"copyright", "copyrightEmail", "license", "status", "statusMessage",
		"supports", "depends", "groups", "inputs", "labels", "parentBaseline",
		"integrity", "originalChecksum", "resultsChecksum", "externalReferences",
	} {
		if v, ok := baseline[key]; ok {
			block[key] = v
		}
	}
	if ext := baselineExtensions(baseline); len(ext) > 0 {
		block["extensions"] = ext
	}
	if generator != nil {
		block["generator"] = generator
	}
	if len(block) == 0 {
		return nil
	}
	return map[string]interface{}{hdfBagKey: block}
}

// buildRulesAndResults maps a baseline's requirements onto the run's rules and
// results. Rules are deduplicated by id because the schema puts uniqueItems on
// the rules array and the spec requires rule ids to identify one descriptor;
// HDF, by contrast, legitimately re-reports a requirement id (overlay chains do
// it constantly), so the later occurrences reuse the first one's rule index and
// carry their own requirement data on their results.
func buildRulesAndResults(
	baseline map[string]interface{},
	baselineName string,
	generator, tool map[string]interface{},
	converterVersion string,
	carried carriedBags,
) ([]interface{}, []interface{}) {
	requirements, _ := exportmap.AsSlice(baseline["requirements"])
	rules := make([]interface{}, 0, len(requirements))
	ruleIndex := map[string]int{}
	results := make([]interface{}, 0, len(requirements))

	for _, raw := range requirements {
		req, ok := exportmap.AsMap(raw)
		if !ok {
			continue
		}
		ruleID := exportmap.GetStr(req, "id")
		owner := false
		idx, seen := ruleIndex[ruleID]
		if !seen {
			idx = len(rules)
			ruleIndex[ruleID] = idx
			rules = append(rules, buildRule(req, baseline, baselineName, generator, tool, converterVersion, carried))
			owner = true
		}
		results = append(results, buildResults(req, baseline, baselineName, ruleID, idx, owner,
			generator, tool, converterVersion, carried)...)
	}
	return rules, results
}

// buildRule maps one HDF requirement onto a SARIF reportingDescriptor.
func buildRule(
	req, baseline map[string]interface{},
	baselineName string,
	generator, tool map[string]interface{},
	converterVersion string,
	carried carriedBags,
) map[string]interface{} {
	ruleID := exportmap.GetStr(req, "id")
	rule := map[string]interface{}{"id": ruleID}
	exportmap.SetIf(rule, "name", exportmap.GetStr(req, "title"))
	if text := exportmap.GetStr(req, "title"); text != "" {
		rule["shortDescription"] = map[string]interface{}{"text": text}
	}
	// fullDescription ← the rationale label and help ← the check label are the
	// exact inverse of what sarif-to-hdf reads back out of those two fields.
	if text := labelledDescription(req, "rationale"); text != "" {
		rule["fullDescription"] = map[string]interface{}{"text": text}
	} else if text := exportmap.DefaultDescription(req); text != "" {
		rule["fullDescription"] = map[string]interface{}{"text": text}
	}
	if text := labelledDescription(req, "check"); text != "" {
		rule["help"] = map[string]interface{}{"text": text}
	}
	exportmap.SetIf(rule, "helpUri", AbsoluteURI(ruleHelpURI(req)))

	config := map[string]interface{}{"level": ruleLevel(req)}
	rule["defaultConfiguration"] = config

	props := map[string]interface{}{}
	if tags := ruleTags(req); len(tags) > 0 {
		props["tags"] = tags
	}
	// security-severity is the SARIF convention for a CVSS base score and what
	// sarif-to-hdf reads to recover impact, so it is emitted only where the
	// requirement actually carries CVSS — writing a STIG severity there would
	// label it as something it is not.
	if score, ok := cvssBaseScore(req); ok {
		props["security-severity"] = strconv.FormatFloat(score, 'f', -1, 64)
	}
	props[hdfBagKey] = requirementBlock(req, baseline, generator, tool, converterVersion)
	setBag(rule, props, carried.find(address{On: onRule, Baseline: baselineName, RuleID: ruleID}))
	return rule
}

// requirementBlock is the lossless HDF carriage block for one requirement: the
// shared export block, minus the per-result rows that live on each SARIF
// result's own bag, plus the sourceLocation the shared block does not carry and
// whose ref this exporter encodes to satisfy SARIF's uri-reference format.
func requirementBlock(
	req, baseline, generator, tool map[string]interface{},
	converterVersion string,
) map[string]interface{} {
	st := exportmap.StatusOf(req)
	block := exportmap.BuildHDFBlock(req, baseline, st.Raw, st.Overridden, st.Suppressed,
		generator, tool, converterVersion)
	delete(block, "results")
	if v, ok := req["sourceLocation"]; ok {
		block["source_location"] = v
	}
	return block
}

// buildResults maps a requirement's HDF results onto SARIF results. A
// requirement with no results emits none: SARIF already represents "this rule
// ran and reported nothing" as a rule with no results, and inventing one would
// be inventing a finding.
func buildResults(
	req, baseline map[string]interface{},
	baselineName, ruleID string,
	ruleIdx int,
	ownsRule bool,
	generator, tool map[string]interface{},
	converterVersion string,
	carried carriedBags,
) []interface{} {
	rows, _ := exportmap.AsSlice(req["results"])
	locations := buildLocations(req, baselineName, ruleID, carried)
	suppressions := buildSuppressions(req)

	out := make([]interface{}, 0, len(rows))
	for ordinal, raw := range rows {
		row, ok := exportmap.AsMap(raw)
		if !ok {
			continue
		}
		kind := resultKind(req, row)
		result := map[string]interface{}{
			"ruleId":    ruleID,
			"ruleIndex": ruleIdx,
			"message":   map[string]interface{}{"text": resultMessage(req, row)},
			"kind":      kind,
		}
		// level and kind are orthogonal axes (SARIF §3.27.9/§3.27.10), and for
		// any kind other than fail the spec allows only the value "none" — which
		// is also the default when level is absent, so it is simply omitted. The
		// rule's defaultConfiguration.level still carries the severity.
		if kind == kindFail {
			result["level"] = ruleLevel(req)
		}
		if len(locations) > 0 {
			result["locations"] = locations
		}
		if len(suppressions) > 0 {
			result["suppressions"] = suppressions
		}
		if fp, pfp := resultFingerprints(req); len(fp) > 0 || len(pfp) > 0 {
			if len(fp) > 0 {
				result["fingerprints"] = fp
			}
			if len(pfp) > 0 {
				result["partialFingerprints"] = pfp
			}
		}
		props := map[string]interface{}{hdfBagKey: resultBlock(req, baseline, row, ownsRule,
			generator, tool, converterVersion)}
		setBag(result, props, carried.find(address{
			On: onResult, Baseline: baselineName, RuleID: ruleID, Ordinal: ordinal,
		}))
		out = append(out, result)
	}
	return out
}

// resultBlock is the HDF data for one result row. The requirement block is
// repeated here only for a requirement that does not own its rule — a duplicate
// id whose data would otherwise be dropped when the first occurrence's rule won.
func resultBlock(
	req, baseline, row map[string]interface{},
	ownsRule bool,
	generator, tool map[string]interface{},
	converterVersion string,
) map[string]interface{} {
	block := map[string]interface{}{"result": withoutRawSourceRecord(row)}
	if !ownsRule {
		block["requirement"] = requirementBlock(req, baseline, generator, tool, converterVersion)
	}
	return block
}

// --- level and kind ---

const kindFail = "fail"

// sarifLevels is the set a carried severity tag must belong to before it is
// trusted as a SARIF level rather than an HDF severity word.
var sarifLevels = map[string]bool{"none": true, "note": true, "warning": true, "error": true}

// ruleLevel resolves the SARIF severity level for a requirement.
//
// A tags.severity written by sarif-to-hdf holds the source level verbatim and is
// the only thing that can restore "none", which HDF impact cannot express —
// impact 0.0 means no impact, not ungraded. Absent that, the level is derived
// from impact on the repo's own severity bands, which is the inverse of the
// alias table sarif-to-hdf maps levels through.
func ruleLevel(req map[string]interface{}) string {
	tags, _ := exportmap.AsMap(req["tags"])
	if level := exportmap.GetStr(tags, "severity"); sarifLevels[level] {
		return level
	}
	impact := 0.0
	if v, ok := req["impact"].(float64); ok {
		impact = v
	}
	switch hdfutil.ImpactToSeverity(impact) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}

// statusKinds maps an HDF Result_Status onto the SARIF kind it belongs to.
// HDF "error" has no importer counterpart: SARIF's "open" is the state where the
// tool had insufficient information to decide, which is what a check that threw
// leaves behind.
var statusKinds = map[string]string{
	"passed":        "pass",
	"failed":        kindFail,
	"notApplicable": "notApplicable",
	"notReviewed":   "review",
	"error":         "open",
}

// importerKindStatus is sarif-to-hdf's kind→status map. Two SARIF kinds collapse
// onto one HDF status in each of two cases, so a carried tags.kind is what
// restores the distinction — but only when it agrees with the status actually
// recorded, so the tag can never contradict the mapped data.
var importerKindStatus = map[string]string{
	"pass":          "passed",
	"open":          "failed",
	"fail":          "failed",
	"review":        "notReviewed",
	"informational": "notApplicable",
	"notApplicable": "notApplicable",
}

// resultKind resolves the SARIF kind for one HDF result row.
func resultKind(req, row map[string]interface{}) string {
	status := exportmap.GetStr(row, "status")
	kind, ok := statusKinds[status]
	if !ok {
		kind = kindFail // SARIF's own default for an unrecognized verdict
	}
	tags, _ := exportmap.AsMap(req["tags"])
	if carried := exportmap.GetStr(tags, "kind"); importerKindStatus[carried] == status && status != "" {
		return carried
	}
	return kind
}

// resultMessage resolves result.message.text, which SARIF requires.
func resultMessage(req, row map[string]interface{}) string {
	if text := exportmap.GetStr(row, "message"); text != "" {
		return text
	}
	if text := exportmap.GetStr(row, "codeDesc"); text != "" {
		return text
	}
	return exportmap.DefaultDescription(req)
}

// --- descriptions, tags, scores ---

// labelledDescription returns the first descriptions[] entry with the given
// label, or "".
func labelledDescription(req map[string]interface{}, label string) string {
	descs, _ := exportmap.AsSlice(req["descriptions"])
	for _, raw := range descs {
		d, ok := exportmap.AsMap(raw)
		if ok && exportmap.GetStr(d, "label") == label {
			return exportmap.GetStr(d, "data")
		}
	}
	return ""
}

// ruleHelpURI restores the helpUri sarif-to-hdf parked in tags, falling back to
// the first external reference HDF carries for the requirement.
func ruleHelpURI(req map[string]interface{}) string {
	tags, _ := exportmap.AsMap(req["tags"])
	if uri := exportmap.GetStr(tags, "helpUri"); uri != "" {
		return uri
	}
	return exportmap.FirstRefURL(req)
}

// ruleTags builds the propertyBag tags array: the CWE taxonomy entries in the
// form GitHub's SARIF ingestion keys on, plus the control ids HDF carries. The
// array is sorted and deduplicated because the schema puts uniqueItems on it.
func ruleTags(req map[string]interface{}) []interface{} {
	seen := map[string]bool{}
	var tags []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			tags = append(tags, s)
		}
	}
	// Each guard is on the ELEMENT, not on the prefixed result: "nist/" + "" is
	// non-empty, so guarding after concatenation emitted a bare "nist/" for an empty
	// entry while the TypeScript peer, which guards the element, emitted nothing.
	// tags is additionalProperties:true, so an empty entry is schema-valid input.
	for _, cwe := range exportmap.StringSlice(req["cwe"]) {
		if cwe != "" {
			add("external/cwe/" + normalizeCWETag(cwe))
		}
	}
	reqTags, _ := exportmap.AsMap(req["tags"])
	for _, nist := range exportmap.StringSlice(reqTags["nist"]) {
		if nist != "" {
			add("nist/" + nist)
		}
	}
	for _, cci := range exportmap.StringSlice(reqTags["cci"]) {
		if cci != "" {
			add("cci/" + cci)
		}
	}
	sort.Strings(tags)
	out := make([]interface{}, 0, len(tags))
	for _, t := range tags {
		out = append(out, t)
	}
	return out
}

// normalizeCWETag renders CWE-79 as cwe-79, the casing the external/cwe/ tag
// convention uses.
func normalizeCWETag(cwe string) string {
	lowered := make([]rune, 0, len(cwe))
	for _, r := range cwe {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		lowered = append(lowered, r)
	}
	return string(lowered)
}

// cvssBaseScore returns the first CVSS base score on the requirement.
func cvssBaseScore(req map[string]interface{}) (float64, bool) {
	entries, _ := exportmap.AsSlice(req["cvss"])
	for _, raw := range entries {
		entry, ok := exportmap.AsMap(raw)
		if !ok {
			continue
		}
		if score, isNum := entry["baseScore"].(float64); isNum {
			return score, true
		}
	}
	return 0, false
}

// resultFingerprints restores the fingerprint maps sarif-to-hdf parked in tags.
func resultFingerprints(req map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	tags, _ := exportmap.AsMap(req["tags"])
	block, _ := exportmap.AsMap(tags["fingerprints"])
	fp, _ := exportmap.AsMap(block["fingerprints"])
	pfp, _ := exportmap.AsMap(block["partialFingerprints"])
	return stringValued(fp), stringValued(pfp)
}

// stringValued keeps only the string-valued entries, which is all SARIF's
// fingerprint maps admit.
func stringValued(m map[string]interface{}) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	out := map[string]interface{}{}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
