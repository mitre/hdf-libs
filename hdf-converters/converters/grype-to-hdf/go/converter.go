package grype_to_hdf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// Grype JSON report input structures

type GrypeReport struct {
	Descriptor     GrypeDescriptor `json:"descriptor"`
	Source         GrypeSource     `json:"source"`
	Distro         *GrypeDistro    `json:"distro,omitempty"`
	Matches        []GrypeMatch    `json:"matches"`
	IgnoredMatches []GrypeMatch    `json:"ignoredMatches,omitempty"`
}

type GrypeDescriptor struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp,omitempty"`
}

type GrypeSource struct {
	Type   string      `json:"type,omitempty"`
	Target GrypeTarget `json:"target"`
}

// GrypeTarget mirrors source.target for an image scan. Grype carries the full
// scanned-image identity here; the converter previously read only userInput and
// dropped the rest. A directory scan emits target as a bare string instead, so
// only UserInput is guaranteed across scan types.
type GrypeTarget struct {
	UserInput      string       `json:"userInput,omitempty"`
	ImageID        string       `json:"imageID,omitempty"`
	ManifestDigest string       `json:"manifestDigest,omitempty"`
	RepoDigests    []string     `json:"repoDigests,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
	Architecture   string       `json:"architecture,omitempty"`
	OS             string       `json:"os,omitempty"`
	Layers         []GrypeLayer `json:"layers,omitempty"`
}

type GrypeLayer struct {
	Digest string `json:"digest,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

type GrypeDistro struct {
	Name    string   `json:"name,omitempty"`
	Version string   `json:"version,omitempty"`
	IDLike  []string `json:"idLike,omitempty"`
}

type GrypeMatch struct {
	Vulnerability          GrypeVulnerability          `json:"vulnerability"`
	RelatedVulnerabilities []GrypeRelatedVulnerability `json:"relatedVulnerabilities,omitempty"`
	MatchDetails           []GrypeMatchDetail          `json:"matchDetails"`
	Artifact               GrypeArtifact               `json:"artifact"`

	// raw is the match exactly as Grype emitted it. Grype carries no literal
	// source snippet, so requirement.code is the whole match re-indented in
	// place — preserving source key order, every field the typed struct does
	// not model, and the source number literals, so the output is byte-identical
	// to the TypeScript twin's JSON.stringify(match, null, 2).
	raw json.RawMessage
}

func (m *GrypeMatch) UnmarshalJSON(data []byte) error {
	type plain GrypeMatch
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*m = GrypeMatch(p)
	m.raw = append(json.RawMessage(nil), data...)
	return nil
}

type GrypeVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource,omitempty"`
	Namespace   string      `json:"namespace,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	URLs        []string    `json:"urls,omitempty"`
	Description string      `json:"description,omitempty"`
	CVSS        []GrypeCVSS `json:"cvss,omitempty"`
	Fix         *GrypeFix   `json:"fix,omitempty"`
	CWE         []string    `json:"cwe,omitempty"`
	EPSS        []GrypeEPSS `json:"epss,omitempty"`
	KEV         *GrypeKEV   `json:"kev,omitempty"`
}

// GrypeEPSS mirrors Grype's vulnerability.epss[] element shape. Grype emits
// the FIRST.org EPSS score and percentile alongside the CVE.
type GrypeEPSS struct {
	CVE        string  `json:"cve,omitempty"`
	EPSS       float64 `json:"epss,omitempty"`
	Percentile float64 `json:"percentile,omitempty"`
	Date       string  `json:"date,omitempty"`
}

// GrypeKEV mirrors Grype's vulnerability.kev block (CISA Known Exploited
// Vulnerabilities). Emitted by newer Grype versions when a CVE appears in the
// CISA KEV catalog.
type GrypeKEV struct {
	InKev     bool   `json:"inKev,omitempty"`
	DateAdded string `json:"dateAdded,omitempty"`
	DueDate   string `json:"dueDate,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

type GrypeRelatedVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource,omitempty"`
	Namespace   string      `json:"namespace,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	URLs        []string    `json:"urls,omitempty"`
	Description string      `json:"description,omitempty"`
	CVSS        []GrypeCVSS `json:"cvss,omitempty"`
}

type GrypeCVSS struct {
	Source  string       `json:"source,omitempty"`
	Type    string       `json:"type,omitempty"`
	Version string       `json:"version,omitempty"`
	Vector  string       `json:"vector,omitempty"`
	Metrics *CVSSMetrics `json:"metrics,omitempty"`

	// raw is the entry exactly as Grype emitted it. The CVSS blob is echoed back
	// into a description verbatim, so re-marshaling the typed fields would silently
	// drop whatever Grype added that this struct does not model (vendorMetadata,
	// for one) and would reorder the keys away from the TypeScript converter's
	// pass-through of the same input.
	raw json.RawMessage
}

func (c *GrypeCVSS) UnmarshalJSON(data []byte) error {
	type plain GrypeCVSS
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*c = GrypeCVSS(p)
	c.raw = append(json.RawMessage(nil), data...)
	return nil
}

func (c GrypeCVSS) MarshalJSON() ([]byte, error) {
	if len(c.raw) > 0 {
		return c.raw, nil
	}
	type plain GrypeCVSS
	return json.Marshal(plain(c))
}

type CVSSMetrics struct {
	BaseScore           float64 `json:"baseScore,omitempty"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

type GrypeFix struct {
	Versions []string `json:"versions,omitempty"`
	State    string   `json:"state,omitempty"` // "fixed", "unknown", "wontfix", "not-fixed"
}

type GrypeMatchDetail struct {
	Type       string                 `json:"type,omitempty"` // "exact-direct-match", "exact-indirect-match", "cpe-match"
	Matcher    string                 `json:"matcher,omitempty"`
	SearchedBy map[string]interface{} `json:"searchedBy,omitempty"`
	Found      map[string]interface{} `json:"found,omitempty"`
}

type GrypeArtifact struct {
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Type      string          `json:"type,omitempty"` // "apk", "rpm", "deb", "npm", etc.
	Locations []GrypeLocation `json:"locations,omitempty"`
	Licenses  []string        `json:"licenses,omitempty"`
	Language  string          `json:"language,omitempty"`
	CPEs      []string        `json:"cpes,omitempty"`
	PURL      string          `json:"purl,omitempty"`
}

type GrypeLocation struct {
	Path    string `json:"path,omitempty"`
	LayerID string `json:"layerID,omitempty"`
}

// Severity to impact mapping.
// Grype maps "critical" to 0.9 (not the standard 1.0) and adds "negligible"=0.0.

var grypeAliases = map[string]float64{
	"critical":   0.9,
	"negligible": 0.0,
}

func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, grypeAliases, 0.5)
}

func isNegligibleOrUnknown(severity string) bool {
	lower := strings.ToLower(severity)
	return lower == "negligible" || lower == "unknown" || lower == ""
}

func getDescription(vuln GrypeVulnerability, relatedVulns []GrypeRelatedVulnerability) string {
	// Use primary vulnerability description if available
	if vuln.Description != "" {
		return vuln.Description
	}

	// Fall back to related vulnerability with matching ID
	for _, related := range relatedVulns {
		if related.ID == vuln.ID && related.Description != "" {
			return related.Description
		}
	}

	return fmt.Sprintf("Vulnerability %s", vuln.ID)
}

func getFixInfo(fix *GrypeFix) string {
	if fix == nil || fix.State == "" {
		return "vulnerability is not known to be fixed in any versions"
	}

	if fix.State == "fixed" && len(fix.Versions) > 0 {
		return fmt.Sprintf("vulnerability is %s for versions %s", fix.State, strings.Join(fix.Versions, ", "))
	}

	return fmt.Sprintf("vulnerability is %s", fix.State)
}

// cvssInfo and relatedCVSS are structs rather than maps because this blob is
// embedded in a description as a string and compared verbatim against the
// TypeScript converter's output — map marshaling would sort the keys instead.
type cvssInfo struct {
	Primary []GrypeCVSS   `json:"primary,omitempty"`
	Related []relatedCVSS `json:"related,omitempty"`
}

type relatedCVSS struct {
	ID         string      `json:"id"`
	DataSource string      `json:"dataSource,omitempty"`
	CVSS       []GrypeCVSS `json:"cvss"`
}

func getCVSSInfo(vuln GrypeVulnerability, relatedVulns []GrypeRelatedVulnerability) string {
	info := cvssInfo{Primary: vuln.CVSS}

	for _, r := range relatedVulns {
		if len(r.CVSS) > 0 {
			info.Related = append(info.Related, relatedCVSS{
				ID:         r.ID,
				DataSource: r.DataSource,
				CVSS:       r.CVSS,
			})
		}
	}

	jsonBytes, err := json.Marshal(info)
	if err != nil {
		return "{}"
	}
	return string(jsonBytes)
}

func getReferences(vuln GrypeVulnerability, relatedVulns []GrypeRelatedVulnerability) []string {
	seen := make(map[string]bool)
	refs := make([]string, 0, len(vuln.URLs))

	// Dedupe while preserving first-seen order. The TS converter dedupes with a
	// Set, which iterates in insertion order; ranging a Go map here instead
	// would randomize the order on every run and never match TS.
	add := func(urls []string) {
		for _, url := range urls {
			if seen[url] {
				continue
			}
			seen[url] = true
			refs = append(refs, url)
		}
	}

	add(vuln.URLs)
	for _, related := range relatedVulns {
		add(related.URLs)
	}

	return refs
}

func buildCodeDesc(match GrypeMatch) string {
	parts := []string{
		fmt.Sprintf("Package: %s@%s", match.Artifact.Name, match.Artifact.Version),
	}

	// Package type if available
	if match.Artifact.Type != "" {
		parts = append(parts, fmt.Sprintf("Type: %s", match.Artifact.Type))
	}

	// Location if available
	if len(match.Artifact.Locations) > 0 && match.Artifact.Locations[0].Path != "" {
		parts = append(parts, fmt.Sprintf("Location: %s", match.Artifact.Locations[0].Path))
	}

	// Match type if available
	if len(match.MatchDetails) > 0 && match.MatchDetails[0].Type != "" {
		parts = append(parts, fmt.Sprintf("Match Type: %s", match.MatchDetails[0].Type))
	}

	return strings.Join(parts, " | ")
}

// buildMatchCode renders the raw match as indented JSON for requirement.code.
// json.Indent re-formats the original bytes in place, preserving source key
// order so the output is byte-identical to the TypeScript twin's
// JSON.stringify(match, null, 2).
func buildMatchCode(match GrypeMatch) string {
	if len(match.raw) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, match.raw, "", "  "); err != nil {
		return "{}"
	}
	return buf.String()
}

// buildCvssEntries maps every entry in vulnerability.cvss[] to a schema Cvss
// primitive. Related-vulnerability CVSS arrays are NOT merged in — the schema
// contract is "one entry per source-CVE CVSS metric set", and the source CVE
// is always the match's primary vulnerability id.
func buildCvssEntries(vuln GrypeVulnerability) []hdf.Cvss {
	if len(vuln.CVSS) == 0 {
		return nil
	}
	out := make([]hdf.Cvss, 0, len(vuln.CVSS))
	for _, c := range vuln.CVSS {
		var bs *float64
		if c.Metrics != nil {
			s := c.Metrics.BaseScore
			bs = &s
		}
		entry := shared.BuildCvss(shared.CvssInput{
			Version:    shared.CvssVersionFromString(c.Version),
			BaseScore:  bs,
			BaseVector: c.Vector,
			Source:     vuln.ID,
		})
		// Parity with the TS converter: an entry with neither score nor
		// vector cannot satisfy the schema anyOf and is skipped.
		if entry.BaseScore == nil && entry.BaseVector == nil {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// mapGrypeTypeToEcosystem translates Grype's artifact.type (apk, deb, rpm,
// npm, python, gem, go-module, java-archive, dotnet, rust-crate, binary, ...)
// to the corresponding schema Ecosystem enum. Anything that doesn't fit the
// schema's published enum (apk, binary, future types) falls back to "generic"
// per the schema's documented convention.
func mapGrypeTypeToEcosystem(grypeType string) hdf.Ecosystem {
	switch strings.ToLower(grypeType) {
	case "rpm":
		return hdf.RPM
	case "deb":
		return hdf.Deb
	case "npm":
		return hdf.Npm
	case "python":
		return hdf.Pypi
	case "gem":
		return hdf.Gem
	case "go-module":
		return hdf.Go
	case "java-archive", "jenkins-plugin":
		return hdf.Maven
	case "dotnet":
		return hdf.Nuget
	case "rust-crate":
		return hdf.Cargo
	default:
		return hdf.Generic
	}
}

// buildAffectedPackages produces a single AffectedPackage from the match's
// artifact block. Grype emits one artifact per match, so the slice always has
// exactly one entry. The first cpes[] element is used (Grype lists multiple
// CPE variations from its alias generator; the first is the canonical form
// matching the package's primary vendor:product identity).
func buildAffectedPackages(match GrypeMatch) []hdf.AffectedPackage {
	artifact := match.Artifact
	name := artifact.Name
	version := artifact.Version
	ecosystem := mapGrypeTypeToEcosystem(artifact.Type)
	pkg := hdf.AffectedPackage{
		Name:      &name,
		Version:   &version,
		Ecosystem: &ecosystem,
	}
	if len(artifact.CPEs) > 0 && artifact.CPEs[0] != "" {
		cpe := artifact.CPEs[0]
		pkg.Cpe = &cpe
	}
	if artifact.PURL != "" {
		purl := artifact.PURL
		pkg.Purl = &purl
	}
	if match.Vulnerability.Fix != nil && match.Vulnerability.Fix.State == "fixed" && len(match.Vulnerability.Fix.Versions) > 0 {
		fixed := match.Vulnerability.Fix.Versions[0]
		if fixed != "" {
			pkg.FixedInVersion = &fixed
		}
	}
	return []hdf.AffectedPackage{pkg}
}

// cweIDPattern matches valid CWE-N identifiers per the MITRE catalog. N is a
// positive integer with no leading zeros.
var cweIDPattern = regexp.MustCompile(`^CWE-[1-9]\d*$`)

// extractCWE filters a Grype-emitted vulnerability.cwe array down to valid
// canonical CWE-N entries. Malformed entries ("CWE-0", "CWE-bogus", "junk")
// are dropped silently — the schema layer would reject them anyway.
func extractCWE(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		if cweIDPattern.MatchString(c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildEpss picks the most-recent EPSS entry from vulnerability.epss[].
// Grype's EPSS array is typically ordered newest-first; we trust that order
// and take element 0 when present.
func buildEpss(epssEntries []GrypeEPSS) *hdf.Epss {
	if len(epssEntries) == 0 {
		return nil
	}
	e := epssEntries[0]
	if e.Date == "" {
		return nil
	}
	return &hdf.Epss{
		Score:      e.EPSS,
		Percentile: e.Percentile,
		Date:       e.Date,
	}
}

// buildKev maps Grype's optional vulnerability.kev block to the schema Kev
// primitive. Returns nil when the block is absent.
func buildKev(k *GrypeKEV) *hdf.Kev {
	if k == nil {
		return nil
	}
	out := &hdf.Kev{InKev: k.InKev}
	if k.DateAdded != "" {
		d := k.DateAdded
		out.DateAdded = &d
	}
	if k.DueDate != "" {
		d := k.DueDate
		out.DueDate = &d
	}
	if k.Notes != "" {
		n := k.Notes
		out.Notes = &n
	}
	return out
}

func convertMatchToRequirement(match GrypeMatch, isIgnored bool, targetName string, startTime time.Time) hdf.EvaluatedRequirement {
	vuln := match.Vulnerability
	cveID := vuln.ID
	severity := vuln.Severity
	impact := getImpact(severity)
	description := getDescription(vuln, match.RelatedVulnerabilities)
	fixInfo := getFixInfo(vuln.Fix)
	cvssInfo := getCVSSInfo(vuln, match.RelatedVulnerabilities)
	refs := getReferences(vuln, match.RelatedVulnerabilities)

	// Determine status. Severity never changes it (unknown-severity
	// convention): a detected vulnerability is failed regardless of rating
	// confidence; only the ignore-rules triage axis differs.
	var status hdf.ResultStatus
	if isIgnored {
		status = hdf.NotReviewed // Ignored by configured rules
	} else {
		status = hdf.Failed
	}

	// Build result message
	messageParts := []string{}
	if isIgnored {
		messageParts = append(messageParts, "This vulnerability was ignored by configured rules.")
	}
	if isNegligibleOrUnknown(severity) && !isIgnored {
		messageParts = append(messageParts, "Manual review required because a Grype rating severity is set to `negligible` or `unknown`.")
	}
	if severity != "" {
		messageParts = append(messageParts, fmt.Sprintf("Severity: %s", severity))
	} else {
		messageParts = append(messageParts, "Severity: unknown")
	}
	messageParts = append(messageParts, fixInfo)
	message := strings.Join(messageParts, " ")

	result := hdf.RequirementResult{
		Status:    status,
		CodeDesc:  buildCodeDesc(match),
		Message:   &message,
		StartTime: startTime,
	}

	// Get CCI tags from curated NIST → CCI mapping
	cciTags := cci.NISTToCCI(shared.DefaultStaticAnalysisNIST)

	// Build tags - only include cci if not empty
	tags := shared.BuildNISTCCITags(shared.DefaultStaticAnalysisNIST, cciTags)
	shared.MarkUnratedSeverity(tags, severity)

	// Build requirement ID
	var requirementID string
	if isIgnored {
		requirementID = fmt.Sprintf("Grype-Ignored-Match/%s", cveID)
	} else {
		requirementID = fmt.Sprintf("Grype/%s", cveID)
	}

	// Build descriptions
	descriptions := []hdf.Description{
		{Label: "default", Data: description},
		{Label: "fix", Data: fixInfo},
		{Label: "check", Data: cvssInfo},
	}

	// Build refs (not a pointer)
	var hdfRefs []hdf.Reference
	if len(refs) > 0 {
		hdfRefs = make([]hdf.Reference, len(refs))
		for i, url := range refs {
			urlCopy := url
			hdfRefs[i] = hdf.Reference{URL: &urlCopy}
		}
	}

	title := fmt.Sprintf("Grype found a vulnerability to %s in %s", cveID, targetName)

	requirement := hdf.EvaluatedRequirement{
		ID:                 requirementID,
		Title:              &title,
		Impact:             impact,
		Code:               hdfutil.Ptr(buildMatchCode(match)),
		Results:            []hdf.RequirementResult{result},
		Tags:               tags,
		Descriptions:       descriptions,
		Refs:               hdfRefs,
		ControlType:        shared.DeriveControlTypeFromTags(shared.DefaultStaticAnalysisNIST),
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
		Cvss:               buildCvssEntries(vuln),
		AffectedPackages:   buildAffectedPackages(match),
		Cwe:                extractCWE(vuln.CWE),
		Epss:               buildEpss(vuln.EPSS),
		Kev:                buildKev(vuln.KEV),
	}

	return requirement
}

// buildComponent surfaces the scan target's identity into a top-level HDF
// component. An image scan yields a containerImage component carrying the image
// digest, id, and distro OS; anything without image identity (e.g. a directory
// scan) falls back to a bare artifact component named for the scan target.
func buildComponent(report GrypeReport, targetName string) hdf.Component {
	t := report.Source.Target
	isImage := t.ImageID != "" || t.ManifestDigest != "" || len(t.RepoDigests) > 0 || len(t.Tags) > 0
	if !isImage {
		return hdf.Component{Name: targetName, Type: hdf.Artifact}
	}

	firstRepoDigest := firstNonEmpty(t.RepoDigests)
	firstTag := firstNonEmpty(t.Tags)

	name := firstRepoDigest
	if name == "" {
		name = firstTag
	}
	if name == "" {
		name = t.ImageID
	}

	component := hdf.Component{Name: name, Type: hdf.ContainerImage}
	if t.ImageID != "" {
		component.ImageID = hdfutil.Ptr(t.ImageID)
	}
	// Image the container was started from: a repoDigest pins it exactly; a tag
	// is the fallback when the scan carries no repoDigest.
	if image := firstRepoDigest; image != "" {
		component.Image = hdfutil.Ptr(image)
	} else if firstTag != "" {
		component.Image = hdfutil.Ptr(firstTag)
	}
	if report.Distro != nil {
		if report.Distro.Name != "" {
			component.OSName = hdfutil.Ptr(report.Distro.Name)
		}
		if report.Distro.Version != "" {
			component.OSVersion = hdfutil.Ptr(report.Distro.Version)
		}
	}
	if integrity := shared.DigestToChecksums(t.ManifestDigest); len(integrity) > 0 {
		component.Integrity = integrity
	}
	if t.Architecture != "" {
		component.Labels = map[string]string{"architecture": t.Architecture}
	}
	return component
}

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ConvertGrypeToHDF converts Grype JSON to HDF
func ConvertGrypeToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("grype: empty input")
	}
	if err := shared.ValidateJSONSize(input, "grype", 0); err != nil {
		return nil, fmt.Errorf("grype: %w", err)
	}

	// Calculate checksum of input data
	resultsChecksum := shared.InputChecksum(input)

	// Parse Grype JSON
	var grypeData GrypeReport
	if err := json.Unmarshal(input, &grypeData); err != nil {
		return nil, fmt.Errorf("invalid Grype JSON: %w", err)
	}

	// Build baseline name from source
	targetName := grypeData.Source.Target.UserInput
	if targetName == "" {
		targetName = "Grype Scan"
	}

	// The scan timestamp anchors every result's start_time; a valid Go zero time is
	// the schema-safe fallback when Grype omits descriptor.timestamp.
	var scanTime *time.Time
	if grypeData.Descriptor.Timestamp != "" {
		if parsed := hdfutil.ParseTimestamp(grypeData.Descriptor.Timestamp); !parsed.IsZero() {
			scanTime = &parsed
		}
	}
	resultStart := time.Time{}
	if scanTime != nil {
		resultStart = *scanTime
	}

	// Build requirements from matches
	requirements := []hdf.EvaluatedRequirement{}

	// Process regular matches
	limitedMatches := shared.LimitSliceWithWarning(grypeData.Matches, 0, "match")
	for _, match := range limitedMatches {
		requirements = append(requirements, convertMatchToRequirement(match, false, targetName, resultStart))
	}

	// Process ignored matches
	limitedIgnored := shared.LimitSliceWithWarning(grypeData.IgnoredMatches, 0, "ignored match")
	for _, match := range limitedIgnored {
		requirements = append(requirements, convertMatchToRequirement(match, true, targetName, resultStart))
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"grype-no-findings",
				fmt.Sprintf("Grype scanned %s and reported zero vulnerable components.", targetName),
				time.Now().UTC(),
			),
		}
	}

	// Create baseline
	baseline := hdf.EvaluatedBaseline{
		Name:            targetName,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	// Build target component from scan source (image identity when present)
	target := buildComponent(grypeData, targetName)

	// Build HDF results
	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "grype-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Grype",
		ToolVersion:      grypeData.Descriptor.Version,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       []hdf.Component{target},
		Timestamp:        scanTime,
	})

	return hdfResult, nil
}
