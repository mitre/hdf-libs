// Package asff converts AWS Security Finding Format (ASFF) documents — the
// format AWS Security Hub and many AWS-integrated tools emit — into HDF Results.
//
// A single ASFF envelope can carry findings from many products, and Security Hub
// findings span multiple compliance standards (CIS, AFSBP, PCI, ...). Because
// hdf-results supports multiple baselines in one document, each product — and
// each Security Hub standard — becomes its own baseline entry, mirroring the
// per-file split the predecessor SAF CLI produced.
package asff

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/awsconfig"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// --- ASFF input structs (only the fields the core converter consumes) ---

type asffFinding struct {
	ID             string            `json:"Id"`
	GeneratorID    string            `json:"GeneratorId"`
	ProductArn     string            `json:"ProductArn"`
	AwsAccountID   string            `json:"AwsAccountId"`
	Title          string            `json:"Title"`
	Description    string            `json:"Description"`
	Types          []string          `json:"Types"`
	SourceURL      string            `json:"SourceUrl"`
	LastObservedAt string            `json:"LastObservedAt"`
	UpdatedAt      string            `json:"UpdatedAt"`
	Severity       asffSeverity      `json:"Severity"`
	Remediation    asffRemediation   `json:"Remediation"`
	ProductFields  map[string]string `json:"ProductFields"`
	Resources      []asffResource    `json:"Resources"`
	Compliance     asffCompliance    `json:"Compliance"`
	Workflow       asffWorkflow      `json:"Workflow"`
	// Vulnerabilities is a standard ASFF field any producer may populate (AWS
	// Inspector, third-party scanners). Mapped generically so its CVE/CVSS/fix
	// data survives regardless of whether the producer is specially handled.
	Vulnerabilities []asffVulnerability `json:"Vulnerabilities"`
}

type asffVulnerability struct {
	ID                 string            `json:"Id"`
	Cvss               []asffCvss        `json:"Cvss"`
	VulnerablePackages []asffVulnPackage `json:"VulnerablePackages"`
	ReferenceUrls      []string          `json:"ReferenceUrls"`
	FixAvailable       string            `json:"FixAvailable"`
	ExploitAvailable   string            `json:"ExploitAvailable"`
	EpssScore          *float64          `json:"EpssScore"`
}

type asffCvss struct {
	Version   string   `json:"Version"`
	BaseScore *float64 `json:"BaseScore"`
	Source    string   `json:"Source"`
}

type asffVulnPackage struct {
	Name           string `json:"Name"`
	Version        string `json:"Version"`
	FixedInVersion string `json:"FixedInVersion"`
}

type asffSeverity struct {
	Label      string   `json:"Label"`
	Normalized *float64 `json:"Normalized"`
}

type asffRemediation struct {
	Recommendation struct {
		Text string `json:"Text"`
		URL  string `json:"Url"`
	} `json:"Recommendation"`
}

type asffResource struct {
	Type      string              `json:"Type"`
	ID        string              `json:"Id"`
	Partition string              `json:"Partition"`
	Region    string              `json:"Region"`
	Details   *asffResourceDetail `json:"Details"`
}

type asffResourceDetail struct {
	// Trivy stashes CVE / package data under Resources[].Details.Other.
	Other map[string]string `json:"Other"`
}

// product identifies which ASFF-emitting tool a finding came from, so the
// converter can apply per-product field overrides (mirrors heimdall2's
// externalProductHandler dispatch at this repo's scale).
type product int

const (
	productDefault product = iota
	productSecurityHub
	productProwler
	productTrivy
)

func productOf(f asffFinding) product {
	company, prod := productArnParts(f.ProductArn)
	switch {
	case prod == "securityhub":
		return productSecurityHub
	case company == "prowler" && prod == "prowler":
		return productProwler
	case company == "aquasecurity" && prod == "aquasecurity":
		return productTrivy
	default:
		return productDefault
	}
}

type asffCompliance struct {
	Status        string             `json:"Status"`
	StatusReasons []asffStatusReason `json:"StatusReasons"`
}

type asffStatusReason struct {
	ReasonCode  string `json:"ReasonCode"`
	Description string `json:"Description"`
}

type asffWorkflow struct {
	Status string `json:"Status"`
}

// standardsControl is a Security Hub standards-doc control. The core converter
// runs without supporting docs (always nil); the parity card wires it in.
type standardsControl struct {
	SeverityRating string
}

// ConvertAsffToHDF converts an ASFF document to HDF Results.
func ConvertAsffToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("asff: empty input")
	}
	if err := shared.ValidateJSONSize(input, "asff", 0); err != nil {
		return nil, fmt.Errorf("asff: %w", err)
	}

	checksum := shared.InputChecksum(input)

	findings, err := parseFindings(input)
	if err != nil {
		return nil, fmt.Errorf("asff: %w", err)
	}

	// Group findings into baselines (per product / per Security Hub standard),
	// preserving first-seen order for deterministic output.
	var baselineOrder []string
	byBaseline := map[string][]asffFinding{}
	var accounts []string
	seenAccount := map[string]bool{}
	for _, f := range findings {
		name := baselineName(f)
		if _, ok := byBaseline[name]; !ok {
			baselineOrder = append(baselineOrder, name)
		}
		byBaseline[name] = append(byBaseline[name], f)
		if f.AwsAccountID != "" && !seenAccount[f.AwsAccountID] {
			seenAccount[f.AwsAccountID] = true
			accounts = append(accounts, f.AwsAccountID)
		}
	}

	baselines := make([]hdf.EvaluatedBaseline, 0, len(baselineOrder))
	for _, name := range baselineOrder {
		baselines = append(baselines, buildBaseline(name, byBaseline[name], checksum))
	}

	// A scanner that ran clean still must emit one baseline with one passed
	// placeholder requirement so the document validates.
	if len(baselines) == 0 {
		baselines = []hdf.EvaluatedBaseline{{
			Name: "AWS Security Finding Format",
			Requirements: []hdf.EvaluatedRequirement{
				shared.BuildNoFindingsRequirement(
					"asff-no-findings",
					"AWS Security Finding Format input contained zero findings.",
					time.Now().UTC(),
				),
			},
			ResultsChecksum: checksum,
		}}
	}

	var components []hdf.Component
	if len(accounts) > 0 {
		refs := baselineNames(baselines)
		for _, acct := range accounts {
			components = append(components, hdf.Component{
				Name:         acct,
				Type:         hdf.CloudAccount,
				BaselineRefs: refs,
			})
		}
	}

	now := time.Now().UTC()
	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "asff-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "AWS Security Finding Format",
		ToolFormat:       "JSON",
		Baselines:        baselines,
		Components:       components,
		Timestamp:        &now,
	}), nil
}

// parseFindings accepts the three shapes real ASFF appears in: a
// `{ "Findings": [...] }` envelope, a bare array, or a single finding object.
func parseFindings(input []byte) ([]asffFinding, error) {
	var wrapper struct {
		Findings json.RawMessage `json:"Findings"`
	}
	// A present "Findings" key is authoritative, even when null or empty — decode
	// its contents (null -> no findings) rather than falling through to the
	// single-object attempt, which would turn {"Findings":null} into one empty
	// finding and diverge from the TypeScript side.
	if err := json.Unmarshal(input, &wrapper); err == nil && wrapper.Findings != nil {
		var fs []asffFinding
		if err := json.Unmarshal(wrapper.Findings, &fs); err == nil {
			return fs, nil
		}
	}
	var arr []asffFinding
	if err := json.Unmarshal(input, &arr); err == nil {
		return arr, nil
	}
	var single asffFinding
	if err := json.Unmarshal(input, &single); err == nil {
		return []asffFinding{single}, nil
	}
	// NDJSON (Prowler): one finding object per line.
	if ndjson, err := parseNDJSON(input); err == nil && len(ndjson) > 0 {
		return ndjson, nil
	}
	return nil, fmt.Errorf("invalid ASFF JSON")
}

func parseNDJSON(input []byte) ([]asffFinding, error) {
	lines := strings.Split(strings.TrimSpace(string(input)), "\n")
	out := make([]asffFinding, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f asffFinding
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			return nil, fmt.Errorf("failed to parse NDJSON line: %w", err)
		}
		out = append(out, f)
	}
	return out, nil
}

func buildBaseline(name string, findings []asffFinding, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	var order []string
	groups := map[string][]asffFinding{}
	for _, f := range findings {
		id := controlID(f)
		if _, ok := groups[id]; !ok {
			order = append(order, id)
		}
		groups[id] = append(groups[id], f)
	}

	reqs := make([]hdf.EvaluatedRequirement, 0, len(order))
	for _, id := range order {
		reqs = append(reqs, buildRequirement(id, groups[id]))
	}

	return hdf.EvaluatedBaseline{
		Name:            name,
		Requirements:    reqs,
		ResultsChecksum: checksum,
	}
}

// buildRequirement consolidates findings sharing a control id into one
// requirement with one result per finding.
func buildRequirement(id string, group []asffFinding) hdf.EvaluatedRequirement {
	impact := 0.0
	for _, f := range group {
		if i := findingImpact(f, nil); i > impact {
			impact = i
		}
	}

	primary := group[0]
	descData := firstNonEmpty(primary.Description, primary.Title)
	if productOf(primary) == productProwler {
		descData = " " // Prowler folds its description into the result codeDesc.
	}
	descriptions := []hdf.Description{{Label: "default", Data: descData}}
	if fix := remediationText(primary); fix != "" {
		descriptions = append(descriptions, hdf.Description{Label: "fix", Data: fix})
	}

	nist := nistTags(group)
	tags := map[string]interface{}{}
	if len(nist) > 0 {
		tags = shared.BuildNISTCCITags(nist, cci.NISTToCCI(nist))
	}

	results := make([]hdf.RequirementResult, 0, len(group))
	for _, f := range group {
		results = append(results, buildResult(f))
	}

	req := hdf.EvaluatedRequirement{
		ID:           id,
		Title:        hdfutil.Ptr(primary.Title),
		Impact:       impact,
		Tags:         tags,
		Descriptions: descriptions,
		Results:      results,
		ControlType:  shared.DeriveControlTypeFromTags(nist),
	}
	var refs []hdf.Reference
	if primary.SourceURL != "" {
		refs = append(refs, hdf.Reference{URL: hdfutil.Ptr(primary.SourceURL)})
	}
	seen := map[string]bool{}
	for _, v := range primary.Vulnerabilities {
		for _, u := range v.ReferenceUrls {
			if u != "" && !seen[u] {
				seen[u] = true
				refs = append(refs, hdf.Reference{URL: hdfutil.Ptr(u)})
			}
		}
	}
	if len(refs) > 0 {
		req.Refs = refs
	}
	return req
}

func buildResult(f asffFinding) hdf.RequirementResult {
	start := hdfutil.ParseTimestamp(firstNonEmpty(f.LastObservedAt, f.UpdatedAt))
	if start.IsZero() {
		start = time.Now().UTC()
	}
	status := mapComplianceStatus(f.Compliance.Status)
	codeDesc := resourceCodeDesc(f)
	message := statusReason(f)
	switch productOf(f) {
	case productProwler:
		codeDesc = f.Description
	case productTrivy:
		status = hdf.Failed
		if m := trivyMessage(f); m != "" {
			message = m
		}
	}
	// A finding may carry structured vulnerability data (Inspector and other
	// scanners). Fold a summary into the message so CVE/CVSS/fix data survives —
	// it is otherwise dropped entirely.
	if v := vulnerabilitySummary(f); v != "" {
		if message != "" {
			message += "\n" + v
		} else {
			message = v
		}
	}
	res := hdf.RequirementResult{Status: status, CodeDesc: codeDesc, StartTime: start}
	if message != "" {
		res.Message = hdfutil.Ptr(message)
	}
	return res
}

// vulnerabilitySummary renders a finding's ASFF Vulnerabilities[] as a compact
// text block: CVE id, CVSS base score, EPSS, exploit/fix availability, and the
// affected packages. Generic — applies to any producer that emits the field.
func vulnerabilitySummary(f asffFinding) string {
	var lines []string
	for _, v := range f.Vulnerabilities {
		parts := []string{v.ID}
		if len(v.Cvss) > 0 && v.Cvss[0].BaseScore != nil {
			parts = append(parts, fmt.Sprintf("CVSS %s %.1f", v.Cvss[0].Version, *v.Cvss[0].BaseScore))
		}
		if v.EpssScore != nil {
			parts = append(parts, fmt.Sprintf("EPSS %.4f", *v.EpssScore))
		}
		if v.ExploitAvailable != "" {
			parts = append(parts, "exploit "+strings.ToLower(v.ExploitAvailable))
		}
		if v.FixAvailable != "" {
			parts = append(parts, "fix "+strings.ToLower(v.FixAvailable))
		}
		for _, p := range v.VulnerablePackages {
			pkg := p.Name + "@" + p.Version
			if p.FixedInVersion != "" {
				pkg += " (fixed in " + p.FixedInVersion + ")"
			}
			parts = append(parts, pkg)
		}
		lines = append(lines, strings.Join(parts, "; "))
	}
	return strings.Join(lines, "\n")
}

// trivyMessage summarizes a Trivy finding's product-specific detail for the
// result message, dispatching on the finding shape Trivy's ASFF template emits:
// a CVE reports the installed vs patched package, a misconfiguration reports the
// remediation message and file location, and a secret reports the file it was
// found in. Details.Other keys are the discriminator — "CVE ID" for
// vulnerabilities, "Message" for misconfigurations, a lone "Filename" for
// secrets.
func trivyMessage(f asffFinding) string {
	if len(f.Resources) == 0 || f.Resources[0].Details == nil {
		return ""
	}
	o := f.Resources[0].Details.Other
	switch {
	case o["CVE ID"] != "":
		patchMsg := "There is no patched version of the package."
		if p := o["Patched Package"]; p != "" {
			patchMsg = fmt.Sprintf("The package has been patched since version(s): %s.", p)
		}
		return fmt.Sprintf("For package %s, the current version that is installed is %s.  %s",
			o["PkgName"], o["Installed Package"], patchMsg)
	case o["Message"] != "":
		msg := o["Message"]
		if loc := trivyLocation(o); loc != "" {
			msg += fmt.Sprintf(" (%s)", loc)
		}
		return msg
	case o["Filename"] != "":
		return fmt.Sprintf("Secret detected in %s.", o["Filename"])
	}
	return ""
}

// trivyLocation renders "file:startLine-endLine" from a misconfiguration
// finding, omitting line numbers Trivy reports as 0 (whole-file findings).
func trivyLocation(o map[string]string) string {
	file := o["Filename"]
	if file == "" {
		return ""
	}
	sl := o["StartLine"]
	if sl == "" || sl == "0" {
		return file
	}
	loc := file + ":" + sl
	if el := o["EndLine"]; el != "" && el != "0" && el != sl {
		loc += "-" + el
	}
	return loc
}

// mapComplianceStatus maps ASFF Compliance.Status to an HDF result status.
// hdf-results has no "skipped": WARNING and NOT_AVAILABLE (no clean pass/fail
// verdict) map to notReviewed; an absent status defaults to failed.
func mapComplianceStatus(status string) hdf.ResultStatus {
	switch status {
	case "PASSED":
		return hdf.Passed
	case "FAILED":
		return hdf.Failed
	case "WARNING", "NOT_AVAILABLE":
		return hdf.NotReviewed
	case "":
		return hdf.Failed
	default:
		return hdf.Error
	}
}

// severityLabelToImpact maps an ASFF severity label to a 0.0–1.0 impact via the
// canonical shared table. asff uses a 0.0 default for unrecognized labels — the
// Go helper takes the default explicitly (the shared TS severityToImpact hardcodes
// 0.5, which is why the TS peer keeps its own 0.0-default variant).
func severityLabelToImpact(label string) float64 {
	return hdfutil.SeverityToImpact(label, 0.0)
}

// findingImpact derives a 0.0–1.0 impact. Suppressed findings are forced to 0.
// When a standards control is matched, its severity rating wins; otherwise the
// finding's Severity.Label is used, with Security Hub's INFORMATIONAL up-graded
// to MEDIUM (Security Hub over-marks findings INFORMATIONAL without context).
func findingImpact(f asffFinding, control *standardsControl) float64 {
	if f.Workflow.Status == "SUPPRESSED" {
		return 0.0
	}
	if control != nil && control.SeverityRating != "" {
		return severityLabelToImpact(control.SeverityRating)
	}
	label := f.Severity.Label
	if isSecurityHub(f) && strings.EqualFold(label, "INFORMATIONAL") {
		label = "MEDIUM"
	}
	if label != "" {
		return severityLabelToImpact(label)
	}
	if f.Severity.Normalized != nil {
		return *f.Severity.Normalized / 100.0
	}
	return 0.0
}

// baselineName is the Level-1 grouping key, per product.
func baselineName(f asffFinding) string {
	switch productOf(f) {
	case productSecurityHub:
		if name := securityHubStandardName(f); name != "" {
			return name
		}
	case productProwler:
		if name := f.ProductFields["ProviderName"]; name != "" {
			return name
		}
	case productTrivy:
		return "Aqua Security - Trivy"
	}
	company, prod := productArnParts(f.ProductArn)
	if company == "" && prod == "" {
		return "AWS Security Finding Format"
	}
	return fmt.Sprintf("%s - %s", company, prod)
}

// controlID is the Level-2 grouping key within a baseline, per product.
func controlID(f asffFinding) string {
	switch productOf(f) {
	case productSecurityHub:
		if c := f.ProductFields["ControlId"]; c != "" {
			return c
		}
		if r := f.ProductFields["RuleId"]; r != "" {
			return r
		}
	case productProwler:
		// Prowler encodes the check id after the first hyphen of GeneratorId.
		if i := strings.Index(f.GeneratorID, "-"); i >= 0 {
			return f.GeneratorID[i+1:]
		}
	case productTrivy:
		if cve := trivyCVE(f); cve != "" {
			return f.GeneratorID + "/" + cve
		}
		return f.GeneratorID + "/" + f.ID
	}
	// Unrecognized producer. A compliance/control finding aggregates per-resource
	// under one requirement, so group it by its generator-derived control ref.
	// A per-instance finding (a vulnerability, a threat) has no such aggregation —
	// key it by the ASFF-unique finding Id so distinct findings never collapse.
	// GeneratorId is NOT guaranteed unique per finding: every Inspector finding
	// shares "AWSInspector", so keying on it lumped every CVE into one requirement.
	if f.Compliance.Status != "" && f.GeneratorID != "" {
		if segs := strings.Split(f.GeneratorID, "/"); segs[len(segs)-1] != "" {
			return segs[len(segs)-1]
		}
	}
	return f.ID
}

func isSecurityHub(f asffFinding) bool {
	return productOf(f) == productSecurityHub
}

// trivyCVE returns the CVE id Trivy stashes under Resources[0].Details.Other.
func trivyCVE(f asffFinding) string {
	if len(f.Resources) > 0 && f.Resources[0].Details != nil {
		return f.Resources[0].Details.Other["CVE ID"]
	}
	return ""
}

// productArnParts pulls the company and product segments from a ProductArn like
// "arn:aws:securityhub:us-east-1::product/aws/securityhub" → ("aws", "securityhub").
func productArnParts(arn string) (company, prod string) {
	if arn == "" {
		return "", ""
	}
	colons := strings.Split(arn, ":")
	tail := colons[len(colons)-1] // "product/aws/securityhub"
	segs := strings.Split(tail, "/")
	if len(segs) >= 3 {
		return segs[1], segs[2]
	}
	return "", ""
}

// securityHubStandardName derives "CIS AWS Foundations Benchmark v1.2.0" from a
// finding's StandardsControlArn, preferring the nicer Types[0] casing when it
// matches the ARN's standard slug (mirrors the SAF CLI grouping key).
func securityHubStandardName(f asffFinding) string {
	arn := f.ProductFields["StandardsControlArn"]
	if arn == "" {
		return ""
	}
	segs := strings.Split(arn, "/")
	if len(segs) < 4 {
		return ""
	}
	slug := segs[len(segs)-4]
	version := segs[len(segs)-2]

	typesLast := ""
	if len(f.Types) > 0 {
		ts := strings.Split(f.Types[0], "/")
		typesLast = ts[len(ts)-1]
	}

	var standard string
	if typesLast != "" && normalizeStd(typesLast) == normalizeStd(slug) {
		standard = strings.ReplaceAll(typesLast, "-", " ")
	} else {
		standard = titleCaseWords(strings.ReplaceAll(slug, "-", " "))
	}
	return fmt.Sprintf("%s v%s", standard, version)
}

func normalizeStd(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "-", " "))
}

func titleCaseWords(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		if w == "" {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

// nistTags derives NIST controls for a requirement's finding group: AWS Config
// rule → NIST via the shared awsconfig mapping, falling back to the static
// analysis default bundle (matching the SAF CLI) when no config rule applies.
func nistTags(group []asffFinding) []string {
	// Trivy CVE findings map to the update/remediation NIST bundle.
	if len(group) > 0 && productOf(group[0]) == productTrivy && trivyCVE(group[0]) != "" {
		return shared.DefaultRemediationNIST
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range group {
		for _, tag := range configRuleNIST(f) {
			if !seen[tag] {
				seen[tag] = true
				out = append(out, tag)
			}
		}
	}
	if len(out) == 0 {
		return shared.DefaultStaticAnalysisNIST
	}
	return out
}

func configRuleNIST(f asffFinding) []string {
	if f.ProductFields["RelatedAWSResources:0/type"] != "AWS::Config::ConfigRule" {
		return nil
	}
	name := f.ProductFields["RelatedAWSResources:0/name"]
	if name == "" {
		return nil
	}
	return awsconfig.NISTControlsBySubstring(name)
}

func remediationText(f asffFinding) string {
	parts := make([]string, 0, 2)
	if f.Remediation.Recommendation.Text != "" {
		parts = append(parts, f.Remediation.Recommendation.Text)
	}
	if f.Remediation.Recommendation.URL != "" {
		parts = append(parts, f.Remediation.Recommendation.URL)
	}
	return strings.Join(parts, "\n")
}

// resourceCodeDesc summarizes a finding's affected resources for the result's
// codeDesc, e.g. "Resources: [Type: AwsAccount, Id: ..., Partition: aws, Region: us-east-1]".
func resourceCodeDesc(f asffFinding) string {
	parts := make([]string, 0, len(f.Resources))
	for _, r := range f.Resources {
		seg := fmt.Sprintf("Type: %s, Id: %s", r.Type, r.ID)
		if r.Partition != "" {
			seg += ", Partition: " + r.Partition
		}
		if r.Region != "" {
			seg += ", Region: " + r.Region
		}
		parts = append(parts, seg)
	}
	return fmt.Sprintf("Resources: [%s]", strings.Join(parts, "; "))
}

// statusReason flattens Compliance.StatusReasons into the result message.
func statusReason(f asffFinding) string {
	var lines []string
	for _, r := range f.Compliance.StatusReasons {
		if r.ReasonCode != "" {
			lines = append(lines, "ReasonCode: "+r.ReasonCode)
		}
		if r.Description != "" {
			lines = append(lines, "Description: "+r.Description)
		}
	}
	return strings.Join(lines, "\n")
}

func baselineNames(baselines []hdf.EvaluatedBaseline) []string {
	names := make([]string, 0, len(baselines))
	for _, b := range baselines {
		names = append(names, b.Name)
	}
	return names
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
