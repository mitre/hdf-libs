// Package nexusiq converts the policy-evaluation result the Nexus IQ CLI writes
// with --result-file (Sonatype Lifecycle) to HDF.
//
// IQ's GitLab dependency-scanning and CycloneDX exports already convert through
// the generic gitlab and cyclonedx converters. What only this native file
// carries is the policy layer: which policy each component violated, its threat
// level, the constraint and condition that fired, and the action IQ attached.
package nexusiq

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	converterName     = "nexusiq"
	vulnerabilityRef  = "SECURITY_VULNERABILITY_REFID"
	unknownComponent  = "Unknown component"
	noFindingsID      = "nexusiq-no-findings"
	alertsPointerRoot = "/policyEvaluationResult/alerts/"
)

// The conditions IQ reasons about vulnerabilities state the score in prose:
// "... with severity >= 7 (severity = 8.1)".
var severityInReason = regexp.MustCompile(`\(severity = ([0-9]+(?:\.[0-9]+)?)\)`)

// Sonatype's own bands for the 0-10 policy threat level.
func threatCategory(level int) string {
	switch {
	case level >= 8:
		return "critical"
	case level >= 4:
		return "severe"
	case level >= 2:
		return "moderate"
	case level == 1:
		return "low"
	default:
		return "none"
	}
}

// impactFor scales the policy threat level onto HDF's 0-1 impact. The threat
// level is the policy author's risk rating, so it governs every alert type,
// not only the ones that carry a CVSS score.
func impactFor(level int) float64 {
	switch {
	case level <= 0:
		return 0
	case level >= 10:
		return 1
	default:
		return float64(level) / 10
	}
}

func isSecurityAlert(t Trigger) bool {
	for _, c := range conditions(t) {
		if c.Reference != nil && c.Reference.Type == vulnerabilityRef {
			return true
		}
	}
	return false
}

func conditions(t Trigger) []ConditionFact {
	var out []ConditionFact
	for _, cf := range t.ComponentFacts {
		for _, k := range cf.ConstraintFacts {
			out = append(out, k.ConditionFacts...)
		}
	}
	return out
}

// The result file carries CVE ids but no CWE, so there is nothing for the
// CWE-to-NIST table to resolve; the controls are the static defaults for a
// vulnerable dependency and for an inventory finding respectively.
func nistFor(t Trigger) []string {
	if isSecurityAlert(t) {
		return append([]string(nil), shared.DefaultRemediationNIST...)
	}
	return append([]string(nil), shared.DefaultComponentManagementNIST...)
}

func coordinate(id *ComponentIdentifier, key string) string {
	if id == nil {
		return ""
	}
	v, _ := id.Coordinates[key].(string)
	return v
}

// packageName prefers the coordinate IQ uses for the format, then the display
// name IQ renders for every identified component.
func packageName(cf ComponentFact) string {
	for _, key := range []string{"name", "packageId", "artifactId"} {
		if v := coordinate(cf.ComponentIdentifier, key); v != "" {
			return v
		}
	}
	if cf.DisplayName != nil {
		return cf.DisplayName.Name
	}
	return ""
}

var purlSafe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// pypiPurl follows the purl spec's pypi rule (lowercase, "_" to "-"). Only pypi
// is built because only pypi has a real fixture behind it; a name or version
// that would need percent-encoding gets no purl rather than a guessed one.
func pypiPurl(name, version string) string {
	if !purlSafe.MatchString(name) || !purlSafe.MatchString(version) {
		return ""
	}
	return "pkg:pypi/" + strings.ReplaceAll(strings.ToLower(name), "_", "-") + "@" + version
}

func affectedPackage(cf ComponentFact) (hdf.AffectedPackage, bool) {
	if cf.ComponentIdentifier == nil {
		return hdf.AffectedPackage{}, false
	}
	name := packageName(cf)
	version := coordinate(cf.ComponentIdentifier, "version")
	purl := ""
	if strings.EqualFold(cf.ComponentIdentifier.Format, "pypi") {
		purl = pypiPurl(name, version)
	}
	pkg := shared.BuildAffectedPackage(shared.AffectedPackageOptions{
		Name:      name,
		Version:   version,
		Ecosystem: shared.EcosystemFromPurlType(cf.ComponentIdentifier.Format),
		Purl:      purl,
	})
	if pkg == nil {
		return hdf.AffectedPackage{}, false
	}
	return *pkg, true
}

// componentLabel names a component for a title: its package coordinates, or,
// for one IQ could not identify, the path it was found at.
func componentLabel(cf ComponentFact) string {
	if cf.ComponentIdentifier == nil {
		if len(cf.Pathnames) > 0 {
			return unknownComponent + " " + cf.Pathnames[0]
		}
		return unknownComponent
	}
	label := strings.TrimSpace(packageName(cf) + " " + coordinate(cf.ComponentIdentifier, "version"))
	if label == "" {
		label = unknownComponent
	}
	if ext := coordinate(cf.ComponentIdentifier, "extension"); ext != "" {
		label += " (" + ext + ")"
	}
	return label
}

func alertLabel(t Trigger) string {
	if len(t.ComponentFacts) == 0 {
		return unknownComponent
	}
	return componentLabel(t.ComponentFacts[0])
}

func distinct(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func externalReferences(t Trigger) []hdf.ExternalReference {
	var ids []string
	for _, c := range conditions(t) {
		if c.Reference != nil && c.Reference.Type == vulnerabilityRef {
			ids = append(ids, c.Reference.Value)
		}
	}
	var refs []hdf.ExternalReference
	for _, id := range distinct(ids) {
		source := "nexus-iq"
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			source = "cve"
		}
		refs = append(refs, hdf.ExternalReference{
			SourceName: source,
			ExternalID: hdfutil.Ptr(id),
			Rel:        hdfutil.Ptr("definition"),
		})
	}
	return refs
}

func nvdRefs(refs []hdf.ExternalReference) []hdf.Reference {
	var out []hdf.Reference
	for _, r := range refs {
		if r.SourceName == "cve" {
			out = append(out, hdf.Reference{URL: hdfutil.Ptr("https://nvd.nist.gov/vuln/detail/" + *r.ExternalID)})
		}
	}
	return out
}

// highestScore is the largest vulnerability score any condition states.
func highestScore(t Trigger) (float64, bool) {
	best, found := 0.0, false
	for _, c := range conditions(t) {
		m := severityInReason.FindStringSubmatch(c.Reason)
		if m == nil {
			continue
		}
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && (!found || v > best) {
			best, found = v, true
		}
	}
	return best, found
}

func tagsFor(a Alert, nist []string, refs []hdf.ExternalReference) map[string]any {
	t := a.Trigger
	tags := shared.BuildNISTCCITags(nist, cci.NISTToCCI(nist))
	tags["nistMapping"] = "static-fallback"
	tags["policyId"] = t.PolicyID
	tags["policyName"] = t.PolicyName
	tags["threatLevel"] = t.ThreatLevel
	tags["threatCategory"] = threatCategory(t.ThreatLevel)

	var constraints, types, hashes []string
	var identifiers []map[string]any
	for _, cf := range t.ComponentFacts {
		hashes = append(hashes, cf.Hash)
		if cf.ComponentIdentifier != nil {
			identifiers = append(identifiers, map[string]any{
				"format":      cf.ComponentIdentifier.Format,
				"coordinates": cf.ComponentIdentifier.Coordinates,
			})
		}
		for _, k := range cf.ConstraintFacts {
			constraints = append(constraints, k.ConstraintName)
			for _, c := range k.ConditionFacts {
				types = append(types, c.ConditionTypeID)
			}
		}
	}
	if v := distinct(constraints); len(v) > 0 {
		tags["constraints"] = v
	}
	if v := distinct(types); len(v) > 0 {
		tags["conditionTypes"] = v
	}
	if v := distinct(hashes); len(v) > 0 {
		tags["componentHash"] = v
	}
	if len(identifiers) > 0 {
		tags["componentIdentifier"] = identifiers
	}
	actions := make([]string, 0, len(a.Actions))
	for _, act := range a.Actions {
		actions = append(actions, act.ActionTypeID)
	}
	if v := distinct(actions); len(v) > 0 {
		tags["actions"] = v
	}
	if score, ok := highestScore(t); ok {
		tags["cvssScore"] = score
	}
	// The requirement id is IQ's violation id, so this is what a CVE gate matches.
	var cves []string
	for _, r := range refs {
		if r.SourceName == "cve" {
			cves = append(cves, *r.ExternalID)
		}
	}
	if len(cves) > 0 {
		tags["cve"] = cves
	}
	return tags
}

func descriptionsFor(t Trigger) []hdf.Description {
	summary := fmt.Sprintf("Nexus IQ policy %s (threat level %d, %s) was violated by %s.",
		t.PolicyName, t.ThreatLevel, threatCategory(t.ThreatLevel), alertLabel(t))
	descriptions := []hdf.Description{{Label: "default", Data: summary}}

	var blocks []string
	for _, cf := range t.ComponentFacts {
		for _, k := range cf.ConstraintFacts {
			lines := []string{k.ConstraintName + ":"}
			for _, c := range k.ConditionFacts {
				lines = append(lines, c.Summary)
			}
			blocks = append(blocks, strings.Join(lines, "\n"))
		}
	}
	if len(blocks) > 0 {
		descriptions = append(descriptions, hdf.Description{Label: "check", Data: strings.Join(blocks, "\n\n")})
	}
	return descriptions
}

func renderAlert(a Alert) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, a.raw, "", "  "); err != nil {
		return "{}"
	}
	return buf.String()
}

func resultFor(a Alert, index int, startTime time.Time) hdf.RequirementResult {
	var reasons, paths []string
	for _, c := range conditions(a.Trigger) {
		reasons = append(reasons, c.Reason)
	}
	for _, cf := range a.Trigger.ComponentFacts {
		paths = append(paths, cf.Pathnames...)
	}
	codeDesc := strings.Join(distinct(reasons), "\n")
	if codeDesc == "" {
		codeDesc = alertLabel(a.Trigger) + " violated " + a.Trigger.PolicyName
	}

	result := hdf.RequirementResult{
		// Every alert is a violation IQ found; the attached action (warn, fail
		// or none) is IQ's enforcement choice, not a different finding status.
		Status:    hdf.Failed,
		CodeDesc:  codeDesc,
		StartTime: startTime,
		RawSourceRecord: &hdf.RawSourceRecord{
			Content:   renderAlert(a),
			Encoding:  hdf.UTF8,
			MediaType: "application/json",
			Pointer:   hdfutil.Ptr(alertsPointerRoot + strconv.Itoa(index)),
		},
	}
	if v := distinct(paths); len(v) > 0 {
		result.Message = hdfutil.Ptr(strings.Join(v, "\n"))
	}
	if len(a.Trigger.ComponentFacts) > 0 {
		cf := a.Trigger.ComponentFacts[0]
		if pkg, ok := affectedPackage(cf); ok {
			if id := shared.PackageInstanceID(deref(pkg.Purl), deref(pkg.Name), deref(pkg.Version)); id != "" {
				result.Resource = hdfutil.Ptr("package")
				result.ResourceID = hdfutil.Ptr(id)
			}
		}
	}
	return result
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func buildRequirement(a Alert, index int, startTime time.Time) hdf.EvaluatedRequirement {
	t := a.Trigger
	nist := nistFor(t)

	id := t.PolicyViolationID
	if id == "" {
		id = "nexusiq-alert-" + strconv.Itoa(index)
	}
	title := alertLabel(t) + " — " + t.PolicyName

	var packages []hdf.AffectedPackage
	for _, cf := range t.ComponentFacts {
		if pkg, ok := affectedPackage(cf); ok {
			packages = append(packages, pkg)
		}
	}
	refs := externalReferences(t)

	return hdf.EvaluatedRequirement{
		ID:                 id,
		Title:              &title,
		Impact:             impactFor(t.ThreatLevel),
		Tags:               tagsFor(a, nist, refs),
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptionsFor(t),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		ExternalReferences: refs,
		Refs:               nvdRefs(refs),
		AffectedPackages:   packages,
		Results:            []hdf.RequirementResult{resultFor(a, index, startTime)},
	}
}

// probe reads the envelope without trusting its types, so a document that only
// resembles a result file is rejected rather than converted to an empty one.
type probe struct {
	ApplicationID          json.RawMessage `json:"applicationId"`
	ScanID                 json.RawMessage `json:"scanId"`
	PolicyEvaluationResult json.RawMessage `json:"policyEvaluationResult"`
}

func hasPrefix(raw json.RawMessage, prefix byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == prefix
}

// violationCounters are the per-band totals IQ reports beside the alerts.
var violationCounters = []string{
	"criticalPolicyViolationCount", "severePolicyViolationCount", "moderatePolicyViolationCount",
}

type parsed struct {
	report  Report
	summary map[string]any
}

// parseInput applies the input guards and decodes the report.
// ConvertNexusIQToHDF and ExpectedRequirementCount share it so they accept and
// reject exactly the same inputs.
func parseInput(input []byte) (*parsed, error) {
	if err := shared.ValidateJSONSize(input, converterName, 0); err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(input)) == 0 {
		return nil, fmt.Errorf("%s: empty input", converterName)
	}

	var p probe
	if err := json.Unmarshal(input, &p); err != nil {
		return nil, fmt.Errorf("%s: failed to parse result file: %w", converterName, err)
	}
	if !hasPrefix(p.ApplicationID, '"') || !hasPrefix(p.ScanID, '"') || !hasPrefix(p.PolicyEvaluationResult, '{') {
		return nil, fmt.Errorf("%s: input does not look like a Nexus IQ policy evaluation result", converterName)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(p.PolicyEvaluationResult, &raw); err != nil {
		return nil, fmt.Errorf("%s: failed to parse policyEvaluationResult: %w", converterName, err)
	}
	alerts := bytes.TrimSpace(raw["alerts"])
	if len(alerts) > 0 && !bytes.Equal(alerts, []byte("null")) && alerts[0] != '[' {
		return nil, fmt.Errorf("%s: policyEvaluationResult.alerts is not an array", converterName)
	}

	var out parsed
	if err := json.Unmarshal(input, &out.report); err != nil {
		return nil, fmt.Errorf("%s: failed to parse result file: %w", converterName, err)
	}

	// IQ's counters let a missing alerts list be told apart from a clean scan.
	if out.report.PolicyEvaluationResult.Alerts == nil {
		total := 0
		for _, key := range violationCounters {
			var n int
			if json.Unmarshal(raw[key], &n) == nil {
				total += n
			}
		}
		if total > 0 {
			return nil, fmt.Errorf("%s: the result reports %d policy violations but carries no alerts", converterName, total)
		}
	}

	out.summary = map[string]any{}
	for key, value := range raw {
		if key == "alerts" || key == "sastAlerts" {
			continue
		}
		var v any
		if json.Unmarshal(value, &v) == nil {
			out.summary[key] = v
		}
	}
	return &out, nil
}

// ExpectedRequirementCount states how many requirements the input must convert
// to: one per alert, or the single no-findings requirement.
func ExpectedRequirementCount(input []byte) (int, string, error) {
	const unit = "Nexus IQ policy alerts, or the no-findings requirement when there are none"
	p, err := parseInput(input)
	if err != nil {
		return 0, unit, err
	}
	if n := len(p.report.PolicyEvaluationResult.Alerts); n > 0 {
		return n, unit, nil
	}
	return 1, unit, nil
}

func reportLinks(r Report) []hdf.ExternalReference {
	links := []struct{ href, media, desc string }{
		{r.ReportHTMLURL, "text/html", "Nexus IQ application report"},
		{r.ReportPDFURL, "application/pdf", "Nexus IQ application report (PDF)"},
		{r.ReportDataURL, "application/json", "Nexus IQ raw report data"},
	}
	var refs []hdf.ExternalReference
	for _, l := range links {
		if l.href == "" {
			continue
		}
		refs = append(refs, hdf.ExternalReference{
			SourceName:  "nexus-iq",
			Href:        hdfutil.Ptr(l.href),
			MediaType:   hdfutil.Ptr(l.media),
			Description: hdfutil.Ptr(l.desc),
			Rel:         hdfutil.Ptr("investigate"),
		})
	}
	return refs
}

// ConvertNexusIQToHDF converts a Nexus IQ CLI policy-evaluation result to HDF.
func ConvertNexusIQToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	p, err := parseInput(input)
	if err != nil {
		return nil, err
	}
	report := p.report
	result := report.PolicyEvaluationResult

	// The result file records no evaluation time.
	startTime := time.Now().UTC()
	requirements := make([]hdf.EvaluatedRequirement, 0, len(result.Alerts))
	for i, a := range result.Alerts {
		requirements = append(requirements, buildRequirement(a, i, startTime))
	}
	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{shared.BuildNoFindingsRequirement(
			noFindingsID,
			fmt.Sprintf("Nexus IQ evaluated %s and reported no policy violations.", report.ApplicationID),
			startTime,
		)}
	}

	context := map[string]any{
		"applicationId": report.ApplicationID,
		"scanId":        report.ScanID,
		"summary":       p.summary,
	}
	if report.Stage != "" {
		context["stage"] = report.Stage
	}
	if report.PolicyAction != "" {
		context["policyAction"] = report.PolicyAction
	}

	title := "Nexus IQ policy evaluation of " + report.ApplicationID
	if report.Stage != "" {
		title += " (" + report.Stage + " stage)"
	}
	baseline := hdf.EvaluatedBaseline{
		Name:            "Nexus IQ Policy Evaluation",
		Title:           &title,
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}
	// No real SAST alert has been seen, so none is mapped; say so rather than
	// let them vanish.
	if n := len(result.SastAlerts); n > 0 {
		context["unconvertedSastAlerts"] = n
		baseline.StatusMessage = hdfutil.Ptr(fmt.Sprintf(
			"%d SAST alerts in the result were not converted; this converter maps component policy alerts only.", n))
	}
	baseline.Extensions = &hdf.Extensions{Passthrough: map[string]any{"nexusiq": context}}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "nexusiq-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Nexus IQ Server",
		ToolFormat:       "json",
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components: []hdf.Component{{
			Type:        hdf.Application,
			Name:        report.ApplicationID,
			ExternalIDS: map[string]string{"nexus-iq": report.ApplicationID},
		}},
		Timestamp:          &startTime,
		ExternalReferences: reportLinks(report),
	}), nil
}
