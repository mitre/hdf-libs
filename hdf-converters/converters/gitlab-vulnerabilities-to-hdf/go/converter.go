// Package gitlab_vulnerabilities_to_hdf converts the envelope assembled by the
// gitlab-vulnerabilities fetcher — a project's GitLab Vulnerability Report read
// over GraphQL, triage state included — into HDF Results.
//
// Status is raw-primary: results[].status is what the scanner last reported on
// the default branch, and every human triage decision (dismissal, confirmation,
// resolution, severity change) rides as an attributed, expiring Status_Override
// so effectiveStatus, effectiveImpact and disposition are computed through the
// shared ladder rather than assigned.
package gitlab_vulnerabilities_to_hdf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cwe"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const (
	converterName = "gitlab-vulnerabilities"
	sourceName    = "GitLab Vulnerability Report"
	generatorName = "gitlab-vulnerabilities-to-hdf"
)

// --- Envelope: the fetcher's assembled document ---

// Envelope is the document the gitlab-vulnerabilities fetcher assembles for
// one project: the instance metadata and project block from its probe query,
// the latest default-branch pipeline from the first page, every page's
// vulnerability nodes, and the time of the fetch.
type Envelope struct {
	Metadata        Metadata        `json:"metadata"`
	Project         Project         `json:"project"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	FetchedAt       string          `json:"fetchedAt"`
}

// Metadata is GraphQL `metadata { enterprise version }`.
type Metadata struct {
	Enterprise bool   `json:"enterprise"`
	Version    string `json:"version"`
}

// Project is the project block of the probe query plus the latest
// default-branch pipeline the fetcher attaches from page 1.
type Project struct {
	ID                          string            `json:"id"`
	FullPath                    string            `json:"fullPath"`
	Name                        string            `json:"name"`
	WebURL                      string            `json:"webUrl"`
	Archived                    bool              `json:"archived"`
	Repository                  *Repository       `json:"repository"`
	SecurityScanners            *SecurityScanners `json:"securityScanners"`
	VulnerabilityStatistic      *Statistic        `json:"vulnerabilityStatistic"`
	LatestDefaultBranchPipeline *Pipeline         `json:"latestDefaultBranchPipeline"`
}

// Repository carries the default branch name.
type Repository struct {
	RootRef string `json:"rootRef"`
}

// SecurityScanners is derived by GitLab from the CI job definitions on the
// latest default-branch pipeline. It says which scanners are configured and
// which jobs succeeded — never whether their reports were ingested.
type SecurityScanners struct {
	Available   []string `json:"available"`
	Enabled     []string `json:"enabled"`
	PipelineRun []string `json:"pipelineRun"`
}

// Statistic is created by ingestion itself, even for zero findings; its
// absence means the Vulnerability Report has never been populated.
type Statistic struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
}

// Pipeline is the latest default-branch pipeline with its per-scanner
// security report summary.
type Pipeline struct {
	IID                   string                     `json:"iid"`
	SHA                   string                     `json:"sha"`
	Ref                   string                     `json:"ref"`
	Status                string                     `json:"status"`
	CreatedAt             string                     `json:"createdAt"`
	FinishedAt            string                     `json:"finishedAt"`
	SecurityReportSummary map[string]*SummarySection `json:"securityReportSummary"`
}

// SummarySection is one report type's ingestion summary.
type SummarySection struct {
	VulnerabilitiesCount int `json:"vulnerabilitiesCount"`
	Scans                struct {
		Nodes []Scan `json:"nodes"`
	} `json:"scans"`
}

// Scan is one security scan record; Status is a GitLab ScanStatus
// (CREATED, SUCCEEDED, JOB_FAILED, REPORT_ERROR, PREPARING,
// PREPARATION_FAILED, PURGED).
type Scan struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// Vulnerability is a GraphQL Vulnerability node with the fields the fetcher
// requests.
type Vulnerability struct {
	ID                      string             `json:"id"`
	UUID                    string             `json:"uuid"`
	Title                   string             `json:"title"`
	Description             string             `json:"description"`
	Severity                string             `json:"severity"`
	ReportType              string             `json:"reportType"`
	State                   string             `json:"state"`
	DetectedAt              string             `json:"detectedAt"`
	ConfirmedAt             *string            `json:"confirmedAt"`
	DismissedAt             *string            `json:"dismissedAt"`
	ResolvedAt              *string            `json:"resolvedAt"`
	UpdatedAt               string             `json:"updatedAt"`
	FalsePositive           bool               `json:"falsePositive"`
	PresentOnDefaultBranch  bool               `json:"presentOnDefaultBranch"`
	ResolvedOnDefaultBranch bool               `json:"resolvedOnDefaultBranch"`
	DismissalReason         *string            `json:"dismissalReason"`
	StateComment            *string            `json:"stateComment"`
	ConfirmedBy             *User              `json:"confirmedBy"`
	DismissedBy             *User              `json:"dismissedBy"`
	ResolvedBy              *User              `json:"resolvedBy"`
	Solution                *string            `json:"solution"`
	VulnerabilityPath       string             `json:"vulnerabilityPath"`
	WebURL                  string             `json:"webUrl"`
	Scanner                 *Scanner           `json:"scanner"`
	PrimaryIdentifier       *Identifier        `json:"primaryIdentifier"`
	Identifiers             []Identifier       `json:"identifiers"`
	Links                   []Link             `json:"links"`
	CVSS                    []CVSSEntry        `json:"cvss"`
	Location                *Location          `json:"location"`
	InitialDetectedPipeline *PipelineRef       `json:"initialDetectedPipeline"`
	LatestDetectedPipeline  *PipelineRef       `json:"latestDetectedPipeline"`
	StateTransitions        TransitionList     `json:"stateTransitions"`
	SeverityOverrides       SeverityChangeList `json:"severityOverrides"`

	// raw is the node exactly as GitLab returned it, kept for requirement.code
	// so nothing the typed view drops (cvss detail, blob paths, full history)
	// is lost in conversion.
	raw json.RawMessage
}

func (v *Vulnerability) UnmarshalJSON(data []byte) error {
	type plain Vulnerability
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*v = Vulnerability(p)
	v.raw = append(json.RawMessage(nil), data...)
	return nil
}

// User is a GraphQL UserCore projection.
type User struct {
	Username    string  `json:"username"`
	Name        string  `json:"name"`
	PublicEmail *string `json:"publicEmail"`
}

// Scanner identifies the analyzer that produced the finding.
type Scanner struct {
	Name       string `json:"name"`
	Vendor     string `json:"vendor"`
	ExternalID string `json:"externalId"`
	ReportType string `json:"reportType"`
}

// Identifier is a scanner rule id, CWE, CVE or similar reference.
type Identifier struct {
	ExternalType string  `json:"externalType"`
	ExternalID   string  `json:"externalId"`
	Name         string  `json:"name"`
	URL          *string `json:"url"`
}

// Link is an external reference attached to the finding.
type Link struct {
	Name *string `json:"name"`
	URL  string  `json:"url"`
}

// CVSSEntry is one vendor's CVSS assessment.
type CVSSEntry struct {
	Vendor       string   `json:"vendor"`
	Vector       string   `json:"vector"`
	Version      float64  `json:"version"`
	BaseScore    *float64 `json:"baseScore"`
	OverallScore *float64 `json:"overallScore"`
	Severity     string   `json:"severity"`
}

// Location is the flattened VulnerabilityLocation union; which fields are set
// depends on Typename.
type Location struct {
	Typename         string      `json:"__typename"`
	File             string      `json:"file"`
	StartLine        *string     `json:"startLine"`
	EndLine          *string     `json:"endLine"`
	BlobPath         *string     `json:"blobPath"`
	VulnerableClass  *string     `json:"vulnerableClass"`
	VulnerableMethod *string     `json:"vulnerableMethod"`
	Dependency       *Dependency `json:"dependency"`
	Image            string      `json:"image"`
	OperatingSystem  string      `json:"operatingSystem"`
	Hostname         string      `json:"hostname"`
	Path             string      `json:"path"`
	Param            string      `json:"param"`
	RequestMethod    string      `json:"requestMethod"`
}

// Dependency is a vulnerable package reference.
type Dependency struct {
	Version string `json:"version"`
	Package struct {
		Name string `json:"name"`
	} `json:"package"`
}

// PipelineRef is the pipeline that first or last detected the finding.
type PipelineRef struct {
	IID       string `json:"iid"`
	SHA       string `json:"sha"`
	Ref       string `json:"ref"`
	CreatedAt string `json:"createdAt"`
}

// TransitionList is the stateTransitions connection, oldest first.
type TransitionList struct {
	Nodes []Transition `json:"nodes"`
}

// Transition is one state change with its author and statement.
type Transition struct {
	FromState       string  `json:"fromState"`
	ToState         string  `json:"toState"`
	CreatedAt       string  `json:"createdAt"`
	Comment         *string `json:"comment"`
	DismissalReason *string `json:"dismissalReason"`
	Author          *User   `json:"author"`
}

// SeverityChangeList is the severityOverrides connection, oldest first.
type SeverityChangeList struct {
	Nodes []SeverityChange `json:"nodes"`
}

// SeverityChange is one human severity override.
type SeverityChange struct {
	OriginalSeverity string `json:"originalSeverity"`
	NewSeverity      string `json:"newSeverity"`
	CreatedAt        string `json:"createdAt"`
	Author           *User  `json:"author"`
}

// --- Parsing and expectation ---

// parseInput applies the converter's input guards and decodes the envelope.
// ConvertGitlabVulnerabilitiesToHDF and ExpectedRequirementCount share it so
// they accept and reject exactly the same inputs.
func parseInput(input []byte) (*Envelope, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("%s: empty input", converterName)
	}
	if err := shared.ValidateJSONSize(input, converterName, 0); err != nil {
		return nil, fmt.Errorf("%s: %w", converterName, err)
	}
	var env Envelope
	if err := json.Unmarshal(input, &env); err != nil {
		return nil, fmt.Errorf("%s: invalid envelope JSON: %w", converterName, err)
	}
	if env.Project.FullPath == "" {
		return nil, fmt.Errorf("%s: input is not a Vulnerability Report envelope (project.fullPath missing)", converterName)
	}
	if !env.Metadata.Enterprise {
		return nil, fmt.Errorf("%s: GitLab Community Edition has no Vulnerability Report; use the gitlab (CI artifact) converter instead", converterName)
	}
	return &env, nil
}

// ExpectedRequirementCount states how many requirements the input must convert
// to: one per vulnerability, or — when the report is empty but was populated
// by ingestion — one no-findings requirement per ingested scanner type. An
// empty report that was never ingested is rejected, exactly as the converter
// rejects it.
func ExpectedRequirementCount(input []byte) (int, string, error) {
	const unit = "GitLab vulnerabilities"
	env, err := parseInput(input)
	if err != nil {
		return 0, unit, err
	}
	if len(env.Vulnerabilities) > 0 {
		limited, _ := hdfutil.LimitSlice(env.Vulnerabilities, 0)
		return len(limited), unit, nil
	}
	if err := ingestionError(env); err != nil {
		return 0, unit, err
	}
	n := len(ingestedReportTypes(env.Project.LatestDefaultBranchPipeline))
	if n == 0 {
		n = 1
	}
	return n, unit, nil
}

// ingestionError classifies an empty vulnerability list. A report that has
// never been populated by ingestion is an error, not a clean document: a
// no-findings pass there would be the one truly silent false pass.
func ingestionError(env *Envelope) error {
	if env.Project.VulnerabilityStatistic != nil {
		return nil
	}
	pipeline := env.Project.LatestDefaultBranchPipeline
	if pipeline == nil {
		return fmt.Errorf("%s: %s has no default-branch pipeline; no security scanner has run", converterName, env.Project.FullPath)
	}
	var created, failed []string
	succeeded := false
	for _, reportType := range sortedSectionKeys(pipeline) {
		for _, scan := range pipeline.SecurityReportSummary[reportType].Scans.Nodes {
			switch scan.Status {
			case "SUCCEEDED":
				succeeded = true
			case "CREATED", "PREPARING":
				created = append(created, reportType)
			case "":
				failed = append(failed, reportType+": status unknown")
			default:
				desc := reportType + ": " + scan.Status
				if len(scan.Errors) > 0 {
					desc += " (" + strings.Join(scan.Errors, "; ") + ")"
				}
				failed = append(failed, desc)
			}
		}
	}
	switch {
	case succeeded:
		// Ingestion ran but left no statistic row — treat the report as populated.
		return nil
	case len(failed) > 0:
		return fmt.Errorf("%s: scanner jobs on the default branch of %s produced no usable report: %s", converterName, env.Project.FullPath, strings.Join(failed, ", "))
	case len(created) > 0:
		return fmt.Errorf("%s: security reports for %s were produced but never ingested (%s stuck at CREATED); the Vulnerability Report requires GitLab Ultimate", converterName, env.Project.FullPath, strings.Join(created, ", "))
	default:
		return fmt.Errorf("%s: no security scanner has run on the default branch of %s", converterName, env.Project.FullPath)
	}
}

func sortedSectionKeys(pipeline *Pipeline) []string {
	keys := make([]string, 0, len(pipeline.SecurityReportSummary))
	for k, section := range pipeline.SecurityReportSummary {
		if section != nil {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// ingestedReportTypes lists the summary sections whose scans succeeded, i.e.
// the scanner types the empty report genuinely covers.
func ingestedReportTypes(pipeline *Pipeline) []string {
	if pipeline == nil {
		return nil
	}
	var types []string
	for _, key := range sortedSectionKeys(pipeline) {
		for _, scan := range pipeline.SecurityReportSummary[key].Scans.Nodes {
			if scan.Status == "SUCCEEDED" {
				types = append(types, key)
				break
			}
		}
	}
	return types
}

// --- Conversion ---

// ConvertGitlabVulnerabilitiesToHDF converts a fetcher envelope to HDF Results.
func ConvertGitlabVulnerabilitiesToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	env, err := parseInput(input)
	if err != nil {
		return nil, err
	}
	fetchedAt := hdfutil.ParseTimestamp(env.FetchedAt)
	if fetchedAt.IsZero() {
		return nil, fmt.Errorf("%s: envelope fetchedAt %q is not a valid timestamp", converterName, env.FetchedAt)
	}
	resultsChecksum := shared.InputChecksum(input)

	var baselines []hdf.EvaluatedBaseline
	if len(env.Vulnerabilities) == 0 {
		if err := ingestionError(env); err != nil {
			return nil, err
		}
		baselines = noFindingsBaselines(env, fetchedAt, resultsChecksum)
	} else {
		baselines = findingBaselines(env, fetchedAt, resultsChecksum)
	}

	opts := shared.HDFResultsOptions{
		GeneratorName:    generatorName,
		ConverterVersion: converterVersion,
		ToolName:         sourceName,
		ToolVersion:      env.Metadata.Version,
		Baselines:        baselines,
		Components:       []hdf.Component{buildComponent(env.Project)},
		Timestamp:        &fetchedAt,
	}
	return shared.BuildHDFResults(opts), nil
}

// findingBaselines groups requirements into one baseline per reportType.
// Baselines are ordered by report type name (requirements keep the API's
// severity order within each), so the document does not depend on which
// finding happened to sort first.
func findingBaselines(env *Envelope, fetchedAt time.Time, checksum *hdf.Checksum) []hdf.EvaluatedBaseline {
	limited := shared.LimitSliceWithWarning(env.Vulnerabilities, 0, "vulnerability")
	byType := map[string][]hdf.EvaluatedRequirement{}
	scanners := map[string]map[string]bool{}
	for i := range limited {
		v := &limited[i]
		reportType := v.ReportType
		if reportType == "" {
			reportType = "GENERIC"
		}
		if _, seen := byType[reportType]; !seen {
			scanners[reportType] = map[string]bool{}
		}
		if v.Scanner != nil && v.Scanner.Name != "" {
			scanners[reportType][v.Scanner.Name] = true
		}
		byType[reportType] = append(byType[reportType], convertVulnerability(v, env.Project, fetchedAt))
	}
	order := make([]string, 0, len(byType))
	for reportType := range byType {
		order = append(order, reportType)
	}
	sort.Strings(order)

	baselines := make([]hdf.EvaluatedBaseline, 0, len(order))
	for _, reportType := range order {
		title := reportTypeLabel(reportType)
		names := make([]string, 0, len(scanners[reportType]))
		for name := range scanners[reportType] {
			names = append(names, name)
		}
		sort.Strings(names)
		summary := fmt.Sprintf("Scanner: %s", strings.Join(names, ", "))
		if len(names) == 0 {
			summary = "Scanner: unknown"
		}
		baselines = append(baselines, hdf.EvaluatedBaseline{
			Name:            sourceName + ": " + title,
			Title:           &title,
			Summary:         &summary,
			Requirements:    byType[reportType],
			ResultsChecksum: checksum,
		})
	}
	return baselines
}

// noFindingsBaselines renders an ingested-but-empty report as one passed
// no-findings requirement per scanner type the ingestion covered.
func noFindingsBaselines(env *Envelope, fetchedAt time.Time, checksum *hdf.Checksum) []hdf.EvaluatedBaseline {
	types := ingestedReportTypes(env.Project.LatestDefaultBranchPipeline)
	if len(types) == 0 {
		types = []string{"generic"}
	}
	var reqs []hdf.EvaluatedRequirement
	for _, key := range types {
		label := reportTypeLabel(summaryKeyToReportType(key))
		reqs = append(reqs, shared.BuildNoFindingsRequirement(
			"gitlab-vulnerability-report-no-findings-"+strings.ToLower(summaryKeyToReportType(key)),
			fmt.Sprintf("GitLab Vulnerability Report for %s lists zero %s vulnerabilities after a successful scan ingestion.", env.Project.FullPath, label),
			fetchedAt,
		))
	}
	title := "No findings"
	summary := fmt.Sprintf("Ingested scanner types: %s", strings.Join(types, ", "))
	return []hdf.EvaluatedBaseline{{
		Name:            sourceName,
		Title:           &title,
		Summary:         &summary,
		Requirements:    reqs,
		ResultsChecksum: checksum,
	}}
}

// summaryKeyToReportType maps a securityReportSummary key (camelCase) to the
// VulnerabilityReportType enum spelling.
func summaryKeyToReportType(key string) string {
	var b strings.Builder
	for i, r := range key {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}

func reportTypeLabel(reportType string) string {
	labels := map[string]string{
		"SAST":                            "SAST",
		"DEPENDENCY_SCANNING":             "Dependency Scanning",
		"CONTAINER_SCANNING":              "Container Scanning",
		"CONTAINER_SCANNING_FOR_REGISTRY": "Container Scanning for Registry",
		"DAST":                            "DAST",
		"SECRET_DETECTION":                "Secret Detection",
		"COVERAGE_FUZZING":                "Coverage Fuzzing",
		"API_FUZZING":                     "API Fuzzing",
		"CLUSTER_IMAGE_SCANNING":          "Cluster Image Scanning",
		"GENERIC":                         "Generic",
	}
	if label, ok := labels[reportType]; ok {
		return label
	}
	return reportType
}

// buildComponent is the provenance the issue asked the fetcher to pre-fill:
// the repository the report describes, the branch it reflects and the commit
// its latest default-branch pipeline scanned.
func buildComponent(p Project) hdf.Component {
	c := hdf.Component{
		Name: p.FullPath,
		Type: hdf.Repository,
		Labels: map[string]string{
			"gitlab/project-id": p.ID,
			"gitlab/full-path":  p.FullPath,
		},
	}
	if p.WebURL != "" {
		u := p.WebURL
		c.URL = &u
	}
	if p.Repository != nil && p.Repository.RootRef != "" {
		b := p.Repository.RootRef
		c.Branch = &b
	}
	if p.LatestDefaultBranchPipeline != nil && p.LatestDefaultBranchPipeline.SHA != "" {
		sha := p.LatestDefaultBranchPipeline.SHA
		c.Commit = &sha
	}
	return c
}

// --- Per-vulnerability conversion ---

func convertVulnerability(v *Vulnerability, project Project, fetchedAt time.Time) hdf.EvaluatedRequirement {
	original, current := severityPair(v)
	title := v.Title
	code := buildVulnCode(v)

	req := hdf.EvaluatedRequirement{
		ID:                 v.UUID,
		Title:              &title,
		Descriptions:       buildDescriptions(v),
		Impact:             hdfutil.SeverityToImpact(original, 0.5),
		Tags:               buildTags(v, project, original, current),
		Refs:               buildRefs(v),
		Code:               &code,
		SourceLocation:     buildSourceLocation(v.Location),
		VerificationMethod: shared.DeriveVerificationMethod(&code),
		Results: []hdf.RequirementResult{{
			Status:    rawStatus(v),
			CodeDesc:  buildCodeDesc(v),
			StartTime: resultStartTime(v, fetchedAt),
		}},
	}
	if ct := shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(req.Tags)); ct != nil {
		req.ControlType = ct
	}

	overrides := append(buildStatusOverrides(v, fetchedAt), buildSeverityOverrides(v, fetchedAt)...)
	if len(overrides) > 0 {
		sortMostRecentFirst(overrides)
		req.StatusOverrides = overrides
		applyEffectivePosture(&req, fetchedAt)
	}
	return req
}

// rawStatus is what the scanner last said on the default branch: the finding
// is present unless GitLab has both stopped detecting it and a human marked it
// resolved. Triage decisions never rewrite it.
func rawStatus(v *Vulnerability) hdf.ResultStatus {
	if v.State == "RESOLVED" && v.ResolvedOnDefaultBranch {
		return hdf.Passed
	}
	return hdf.Failed
}

// severityPair returns the scanner's original severity and the current one.
// GitLab's `severity` already reflects human overrides, so the original is
// recovered from the oldest override when there is one.
func severityPair(v *Vulnerability) (original, current string) {
	current = v.Severity
	original = current
	if n := len(v.SeverityOverrides.Nodes); n > 0 && v.SeverityOverrides.Nodes[0].OriginalSeverity != "" {
		original = v.SeverityOverrides.Nodes[0].OriginalSeverity
	}
	return original, current
}

func resultStartTime(v *Vulnerability, fetchedAt time.Time) time.Time {
	if v.LatestDetectedPipeline != nil {
		if ts := hdfutil.ParseTimestamp(v.LatestDetectedPipeline.CreatedAt); !ts.IsZero() {
			return ts
		}
	}
	if ts := hdfutil.ParseTimestamp(v.DetectedAt); !ts.IsZero() {
		return ts
	}
	return fetchedAt
}

func buildDescriptions(v *Vulnerability) []hdf.Description {
	text := v.Description
	if text == "" {
		text = v.Title
	}
	descriptions := []hdf.Description{{Label: "default", Data: text}}
	if v.Solution != nil && *v.Solution != "" {
		descriptions = append(descriptions, hdf.Description{Label: "fix", Data: *v.Solution})
	}
	return descriptions
}

// buildTags carries every triage field losslessly (always present, null when
// absent) alongside the NIST/CCI mapping and the identifier extras.
func buildTags(v *Vulnerability, project Project, original, current string) map[string]interface{} {
	nist := buildNistTags(v.Identifiers)
	tags := shared.BuildNISTCCITagsWithExtras(nist, cci.NISTToCCI(nist), collectIdentifierExtras(v.Identifiers))
	shared.MarkUnratedSeverity(tags, current)

	tags["gitlab/id"] = v.ID
	tags["gitlab/uuid"] = v.UUID
	tags["gitlab/webUrl"] = v.WebURL
	tags["gitlab/project"] = project.FullPath
	tags["gitlab/reportType"] = v.ReportType
	tags["gitlab/severity"] = current
	tags["gitlab/originalSeverity"] = original
	tags["gitlab/state"] = v.State
	tags["gitlab/dismissalReason"] = nullableString(v.DismissalReason)
	tags["gitlab/stateComment"] = nullableString(v.StateComment)
	tags["gitlab/falsePositive"] = v.FalsePositive
	tags["gitlab/presentOnDefaultBranch"] = v.PresentOnDefaultBranch
	tags["gitlab/resolvedOnDefaultBranch"] = v.ResolvedOnDefaultBranch
	tags["gitlab/detectedAt"] = v.DetectedAt
	tags["gitlab/updatedAt"] = v.UpdatedAt
	tags["gitlab/confirmedAt"] = nullableString(v.ConfirmedAt)
	tags["gitlab/confirmedBy"] = userTag(v.ConfirmedBy)
	tags["gitlab/dismissedAt"] = nullableString(v.DismissedAt)
	tags["gitlab/dismissedBy"] = userTag(v.DismissedBy)
	tags["gitlab/resolvedAt"] = nullableString(v.ResolvedAt)
	tags["gitlab/resolvedBy"] = userTag(v.ResolvedBy)
	tags["gitlab/initialDetectedPipeline"] = pipelineTag(v.InitialDetectedPipeline)
	tags["gitlab/latestDetectedPipeline"] = pipelineTag(v.LatestDetectedPipeline)
	tags["gitlab/scanner"] = scannerTag(v.Scanner)
	tags["gitlab/stateTransitionCount"] = len(v.StateTransitions.Nodes)
	if len(v.StateTransitions.Nodes) > 0 && v.StateTransitions.Nodes[len(v.StateTransitions.Nodes)-1].ToState != v.State {
		tags["gitlab/stateHistoryInconsistent"] = true
	}
	return tags
}

func nullableString(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func userTag(u *User) interface{} {
	if u == nil {
		return nil
	}
	return u.Username
}

func pipelineTag(p *PipelineRef) interface{} {
	if p == nil {
		return nil
	}
	return map[string]interface{}{"iid": p.IID, "sha": p.SHA, "ref": p.Ref, "createdAt": p.CreatedAt}
}

func scannerTag(s *Scanner) interface{} {
	if s == nil {
		return nil
	}
	return map[string]interface{}{"name": s.Name, "vendor": s.Vendor, "externalId": s.ExternalID}
}

func buildNistTags(identifiers []Identifier) []string {
	seen := map[string]bool{}
	var controls []string
	for _, id := range identifiers {
		if !strings.EqualFold(id.ExternalType, "cwe") || id.ExternalID == "" {
			continue
		}
		for _, ctrl := range cwe.NISTControls(id.ExternalID) {
			if !seen[ctrl] {
				seen[ctrl] = true
				controls = append(controls, ctrl)
			}
		}
	}
	if len(controls) > 0 {
		return controls
	}
	return shared.DefaultStaticAnalysisNIST
}

func collectIdentifierExtras(identifiers []Identifier) map[string]interface{} {
	grouped := map[string][]string{}
	var order []string
	for _, id := range identifiers {
		if id.ExternalType == "" || id.ExternalID == "" {
			continue
		}
		key := strings.ToLower(id.ExternalType)
		if _, seen := grouped[key]; !seen {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], id.ExternalID)
	}
	extras := make(map[string]interface{}, len(order))
	for _, key := range order {
		extras[key] = hdfutil.StringsToInterfaces(grouped[key])
	}
	return extras
}

// buildRefs collects the finding's own page plus every identifier and link
// URL, de-duplicated.
func buildRefs(v *Vulnerability) []hdf.Reference {
	var refs []hdf.Reference
	seen := map[string]bool{}
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		uc := u
		refs = append(refs, hdf.Reference{URL: &uc})
	}
	add(v.WebURL)
	for _, id := range v.Identifiers {
		if id.URL != nil {
			add(*id.URL)
		}
	}
	for _, link := range v.Links {
		add(link.URL)
	}
	return refs
}

// buildVulnCode renders the raw node as indented JSON for requirement.code,
// preserving source key order so it is byte-identical to the TypeScript twin's
// JSON.stringify(node, null, 2).
func buildVulnCode(v *Vulnerability) string {
	if len(v.raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, v.raw, "", "  "); err != nil {
		return "{}"
	}
	return buf.String()
}

func buildSourceLocation(loc *Location) *hdf.SourceLocation {
	if loc == nil || loc.File == "" {
		return nil
	}
	ref := loc.File
	sl := &hdf.SourceLocation{Ref: &ref}
	if line := parseLine(loc.StartLine); line != nil {
		sl.Line = line
	} else if line := parseLine(loc.EndLine); line != nil {
		sl.Line = line
	}
	return sl
}

func parseLine(s *string) *float64 {
	if s == nil || *s == "" {
		return nil
	}
	n, err := strconv.Atoi(*s)
	if err != nil {
		return nil
	}
	f := float64(n)
	return &f
}

// buildCodeDesc renders the location for the result, by union member.
func buildCodeDesc(v *Vulnerability) string {
	loc := v.Location
	if loc == nil {
		return fmt.Sprintf("Report type: %s", v.ReportType)
	}
	var parts []string
	switch loc.Typename {
	case "VulnerabilityLocationSast", "VulnerabilityLocationSecretDetection", "VulnerabilityLocationCoverageFuzzing", "VulnerabilityLocationGeneric":
		if loc.File != "" {
			parts = append(parts, "File: "+loc.File)
		}
		if loc.StartLine != nil && *loc.StartLine != "" {
			if loc.EndLine != nil && *loc.EndLine != "" && *loc.EndLine != *loc.StartLine {
				parts = append(parts, fmt.Sprintf("Line: %s-%s", *loc.StartLine, *loc.EndLine))
			} else {
				parts = append(parts, "Line: "+*loc.StartLine)
			}
		}
		if loc.VulnerableClass != nil && *loc.VulnerableClass != "" {
			parts = append(parts, "Class: "+*loc.VulnerableClass)
		}
		if loc.VulnerableMethod != nil && *loc.VulnerableMethod != "" {
			parts = append(parts, "Method: "+*loc.VulnerableMethod)
		}
	case "VulnerabilityLocationDependencyScanning":
		if loc.File != "" {
			parts = append(parts, "File: "+loc.File)
		}
		if pkg := packageLabel(loc.Dependency); pkg != "" {
			parts = append(parts, "Package: "+pkg)
		}
	case "VulnerabilityLocationContainerScanning", "VulnerabilityLocationClusterImageScanning":
		if loc.Image != "" {
			parts = append(parts, "Image: "+loc.Image)
		}
		if loc.OperatingSystem != "" {
			parts = append(parts, "OS: "+loc.OperatingSystem)
		}
		if pkg := packageLabel(loc.Dependency); pkg != "" {
			parts = append(parts, "Package: "+pkg)
		}
	case "VulnerabilityLocationDast":
		if loc.Hostname != "" {
			parts = append(parts, "URL: "+loc.Hostname+loc.Path)
		}
		if loc.RequestMethod != "" {
			parts = append(parts, "Method: "+loc.RequestMethod)
		}
		if loc.Param != "" {
			parts = append(parts, "Param: "+loc.Param)
		}
	default:
		raw, _ := json.Marshal(loc)
		return "Location: " + string(raw)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Report type: %s", v.ReportType)
	}
	return strings.Join(parts, " | ")
}

func packageLabel(d *Dependency) string {
	if d == nil || d.Package.Name == "" {
		return ""
	}
	if d.Version != "" {
		return d.Package.Name + "@" + d.Version
	}
	return d.Package.Name
}

// --- Triage state → overrides ---

// decision is what a human state change maps to in HDF.
type decision struct {
	overrideType  hdf.OverrideType
	status        hdf.ResultStatus
	justification *hdf.Justification
	defaultReason string
}

// decisionFor maps a transition into a triage state onto an override, or
// returns false when the state carries no override (DETECTED, CONFIRMED, and
// RESOLVED once the scanner itself no longer reports the finding).
func decisionFor(toState string, dismissalReason *string, scannerResolved bool) (decision, bool) {
	switch toState {
	case "DISMISSED":
		reason := ""
		if dismissalReason != nil {
			reason = *dismissalReason
		}
		return dismissalDecision(reason)
	case "RESOLVED":
		if scannerResolved {
			return decision{}, false
		}
		return decision{overrideType: hdf.Attestation, status: hdf.Passed, defaultReason: "Marked resolved in GitLab"}, true
	case "DETECTED", "CONFIRMED":
		return decision{}, false
	default:
		return decision{}, false
	}
}

func dismissalDecision(reason string) (decision, bool) {
	inline := hdf.InlineMitigationsAlreadyExist
	notInPath := hdf.VulnerableCodeNotInExecutePath
	switch reason {
	case "FALSE_POSITIVE":
		return decision{overrideType: hdf.FalsePositive, status: hdf.NotApplicable, defaultReason: "Dismissed as FALSE_POSITIVE in GitLab"}, true
	case "ACCEPTABLE_RISK":
		return decision{overrideType: hdf.OverrideTypeWaiver, status: hdf.Passed, defaultReason: "Dismissed as ACCEPTABLE_RISK in GitLab"}, true
	case "MITIGATING_CONTROL":
		return decision{overrideType: hdf.OverrideTypeWaiver, status: hdf.Passed, justification: &inline, defaultReason: "Dismissed as MITIGATING_CONTROL in GitLab"}, true
	case "USED_IN_TESTS":
		return decision{overrideType: hdf.OverrideTypeWaiver, status: hdf.NotApplicable, justification: &notInPath, defaultReason: "Dismissed as USED_IN_TESTS in GitLab"}, true
	case "NOT_APPLICABLE", "":
		return decision{overrideType: hdf.OverrideTypeWaiver, status: hdf.NotApplicable, defaultReason: "Dismissed as NOT_APPLICABLE in GitLab"}, true
	default:
		return decision{overrideType: hdf.OverrideTypeWaiver, status: hdf.NotApplicable, defaultReason: "Dismissed as " + reason + " in GitLab"}, true
	}
}

// buildStatusOverrides replays the full state history: one override per
// transition into a mapped state, oldest first. A revert (a transition back to
// DETECTED) creates no override; it closes the previous one by setting its
// expiry to the revert time, so the ladder stops it governing while the record
// stays intact. When GitLab returned no history for a triaged finding, the
// single governing override is synthesized from the current-state fields.
func buildStatusOverrides(v *Vulnerability, fetchedAt time.Time) []hdf.StatusOverride {
	scannerResolved := v.State == "RESOLVED" && v.ResolvedOnDefaultBranch
	var overrides []hdf.StatusOverride
	for _, tr := range v.StateTransitions.Nodes {
		if tr.ToState == "DETECTED" {
			if n := len(overrides); n > 0 {
				if at := hdfutil.ParseTimestamp(tr.CreatedAt); !at.IsZero() {
					overrides[n-1].ExpiresAt = at
				}
			}
			continue
		}
		d, ok := decisionFor(tr.ToState, tr.DismissalReason, scannerResolved)
		if !ok {
			continue
		}
		appliedAt := firstTime(fetchedAt, tr.CreatedAt, v.UpdatedAt, v.DetectedAt)
		overrides = append(overrides, newOverride(v, d, appliedAt, tr.Comment, tr.Author))
	}
	if len(v.StateTransitions.Nodes) > 0 {
		last := v.StateTransitions.Nodes[len(v.StateTransitions.Nodes)-1]
		if last.ToState == v.State {
			return overrides
		}
	}
	// No usable history for the current state: synthesize it.
	if d, ok := decisionFor(v.State, v.DismissalReason, scannerResolved); ok {
		at, by := currentDecisionProvenance(v, fetchedAt)
		overrides = append(overrides, newOverride(v, d, at, v.StateComment, by))
	}
	return overrides
}

func currentDecisionProvenance(v *Vulnerability, fetchedAt time.Time) (time.Time, *User) {
	switch v.State {
	case "DISMISSED":
		return firstTime(fetchedAt, derefString(v.DismissedAt), v.UpdatedAt, v.DetectedAt), v.DismissedBy
	case "RESOLVED":
		return firstTime(fetchedAt, derefString(v.ResolvedAt), v.UpdatedAt, v.DetectedAt), v.ResolvedBy
	default:
		// Only dismissals and resolutions synthesize an override; anything else
		// reaching here is dated but unattributed.
		return firstTime(fetchedAt, v.UpdatedAt, v.DetectedAt), nil
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// firstTime parses the first candidate that is a valid timestamp, falling
// back to the fetch time when the source carries none, so an override always
// has a real, deterministic date and both language twins agree on it.
func firstTime(fetchedAt time.Time, candidates ...string) time.Time {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if ts := hdfutil.ParseTimestamp(c); !ts.IsZero() {
			return ts
		}
	}
	return fetchedAt
}

func newOverride(v *Vulnerability, d decision, appliedAt time.Time, comment *string, author *User) hdf.StatusOverride {
	reason := d.defaultReason
	if comment != nil && strings.TrimSpace(*comment) != "" {
		reason = *comment
	}
	status := d.status
	o := hdf.StatusOverride{
		Type:          d.overrideType,
		Status:        &status,
		Reason:        reason,
		Justification: d.justification,
		AppliedBy:     identityFor(author),
		AppliedAt:     appliedAt,
		ExpiresAt:     shared.DefaultOverrideExpiry(appliedAt),
	}
	if v.WebURL != "" {
		href := v.WebURL
		o.ExternalReferences = []hdf.ExternalReference{{SourceName: sourceName, Href: &href}}
	}
	return o
}

// identityFor prefers a public email, then the username; a decision GitLab
// recorded without an author (automation) is attributed to the system, never
// to a fabricated person.
func identityFor(u *User) hdf.Identity {
	if u != nil {
		var desc *string
		if u.Name != "" {
			n := u.Name
			desc = &n
		}
		if u.PublicEmail != nil && *u.PublicEmail != "" {
			return hdf.Identity{Type: hdf.Email, Identifier: *u.PublicEmail, Description: desc}
		}
		if u.Username != "" {
			return hdf.Identity{Type: hdf.Username, Identifier: u.Username, Description: desc}
		}
	}
	auto := "GitLab automatic state change"
	return hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: "gitlab", Description: &auto}
}

// buildSeverityOverrides turns each human severity change into an impact-only
// riskAdjustment; requirement.impact keeps the scanner's original severity.
func buildSeverityOverrides(v *Vulnerability, fetchedAt time.Time) []hdf.StatusOverride {
	var overrides []hdf.StatusOverride
	for _, sc := range v.SeverityOverrides.Nodes {
		appliedAt := firstTime(fetchedAt, sc.CreatedAt, v.UpdatedAt, v.DetectedAt)
		o := hdf.StatusOverride{
			Type:      hdf.RiskAdjustment,
			Impact:    &hdf.ImpactOverride{Value: hdfutil.SeverityToImpact(sc.NewSeverity, 0.5)},
			Reason:    fmt.Sprintf("Severity changed from %s to %s in GitLab", sc.OriginalSeverity, sc.NewSeverity),
			AppliedBy: identityFor(sc.Author),
			AppliedAt: appliedAt,
			ExpiresAt: shared.DefaultOverrideExpiry(appliedAt),
		}
		if v.WebURL != "" {
			href := v.WebURL
			o.ExternalReferences = []hdf.ExternalReference{{SourceName: sourceName, Href: &href}}
		}
		overrides = append(overrides, o)
	}
	return overrides
}

// sortMostRecentFirst orders overrides newest first. GitLab timestamps have
// second resolution, so decisions made in the same second tie on AppliedAt;
// reversing the oldest-first history before the stable sort keeps the later
// decision ahead of the one it superseded.
func sortMostRecentFirst(overrides []hdf.StatusOverride) {
	for i, j := 0, len(overrides)-1; i < j; i, j = i+1, j-1 {
		overrides[i], overrides[j] = overrides[j], overrides[i]
	}
	sort.SliceStable(overrides, func(i, j int) bool {
		return overrides[i].AppliedAt.After(overrides[j].AppliedAt)
	})
}

// applyEffectivePosture fills effectiveStatus, effectiveImpact and
// disposition from the shared ladder, judged at the fetch time so the output
// is deterministic for a given envelope.
func applyEffectivePosture(req *hdf.EvaluatedRequirement, ref time.Time) {
	inputs := shared.StatusOverrideInputs(req.StatusOverrides)

	status := hdf.ResultStatus(hdfutil.ComputeEffectiveStatus(shared.RequirementStatusInput(*req), ref))
	req.EffectiveStatus = &status

	if i := hdfutil.GoverningOverrideIndex(inputs, func(i int) bool { return req.StatusOverrides[i].Impact != nil }, ref); i >= 0 {
		impact := req.StatusOverrides[i].Impact.Value
		req.EffectiveImpact = &impact
	}
	if i := hdfutil.GoverningOverrideIndex(inputs, func(i int) bool {
		o := req.StatusOverrides[i]
		return o.Status != nil || o.Impact != nil
	}, ref); i >= 0 {
		disposition := req.StatusOverrides[i].Type
		req.Disposition = &disposition
	}
}
