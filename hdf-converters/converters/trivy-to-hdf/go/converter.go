// Package trivy converts Trivy scanner output to HDF. It is a router: native
// Trivy JSON (SchemaVersion 2) is parsed here, while Trivy's other output
// formats (SARIF, CycloneDX, ASFF, GitLab) are delegated to their existing
// converters. This lets `--from trivy` accept any Trivy output shape.
package trivy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	asff "github.com/mitre/hdf-libs/hdf-converters/v3/converters/asff-to-hdf/go"
	cyclonedx "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cyclonedx-to-hdf/go"
	gitlab "github.com/mitre/hdf-libs/hdf-converters/v3/converters/gitlab-to-hdf/go"
	sarif "github.com/mitre/hdf-libs/hdf-converters/v3/converters/sarif-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-mappings/go/v3/cci"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

const baselineName = "Trivy Scan"

// Trivy severity is UPPERCASE; critical maps to 0.9 (the rest fall through to
// the shared standard map: high 0.7, medium 0.5, low 0.3, none/info 0.0).
var severityAliases = map[string]float64{"critical": 0.9}

var cweIDPattern = regexp.MustCompile(`^CWE-[1-9]\d*$`)

// staticNISTCCI is the fallback NIST/CCI tag set for scanner findings with no
// per-finding NIST signal, resolved once (mirrors grype-to-hdf).
var staticCCI = cci.NISTToCCI(shared.DefaultStaticAnalysisNIST)

// ConvertTrivyToHDF routes Trivy output to HDF Results: native Trivy JSON is
// parsed directly; SARIF / CycloneDX / ASFF / GitLab are delegated to their
// converters. Returns an error for input that is not a recognized Trivy format.
func ConvertTrivyToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if err := shared.ValidateJSONSize(input, "trivy", 0); err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, fmt.Errorf("trivy: empty input")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(input, &probe); err != nil {
		return nil, fmt.Errorf("trivy: input is not a JSON object: %w", err)
	}

	switch {
	case isNativeTrivy(probe):
		return convertNative(input, converterVersion)
	case stringFieldEquals(probe, "bomFormat", "CycloneDX"):
		return cyclonedx.ConvertCycloneDXToHDF(input, converterVersion)
	case hasKey(probe, "runs") && hasKey(probe, "version"):
		return sarif.ConvertSarifToHDF(input, converterVersion)
	case hasKey(probe, "Findings") || hasKey(probe, "ProductArn"):
		return asff.ConvertAsffToHDF(input, converterVersion)
	case hasKey(probe, "vulnerabilities"):
		return gitlab.ConvertGitlabToHDF(input, converterVersion)
	default:
		return nil, fmt.Errorf("trivy: not a recognized Trivy output format (native JSON, SARIF, CycloneDX, ASFF, or GitLab)")
	}
}

// isNativeTrivy keys on markers the delegate formats lack: a numeric
// SchemaVersion plus ArtifactName/ArtifactType. Results may be absent (a clean
// scan omits it entirely), so it is not required.
func isNativeTrivy(m map[string]json.RawMessage) bool {
	return hasKey(m, "SchemaVersion") && hasKey(m, "ArtifactName") && hasKey(m, "ArtifactType")
}

func hasKey(m map[string]json.RawMessage, k string) bool {
	_, ok := m[k]
	return ok
}

func stringFieldEquals(m map[string]json.RawMessage, key, want string) bool {
	raw, ok := m[key]
	if !ok {
		return false
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && s == want
}

// --- native JSON model ------------------------------------------------------

type trivyReport struct {
	SchemaVersion int
	ArtifactName  string
	ArtifactType  string
	CreatedAt     string
	Trivy         *struct{ Version string }
	Metadata      *trivyMetadata
	Results       []trivyResult
}

type trivyMetadata struct {
	OS          *struct{ Family, Name string }
	ImageID     string
	RepoTags    []string
	RepoDigests []string
	ImageConfig json.RawMessage
}

type trivyResult struct {
	Target            string
	Class             string
	Type              string
	Vulnerabilities   []json.RawMessage
	Misconfigurations []json.RawMessage
	Secrets           []json.RawMessage
	Licenses          []json.RawMessage
}

type trivyCVSS struct {
	V2Vector, V3Vector, V40Vector string
	V2Score, V3Score, V40Score    *float64
}

type trivyVuln struct {
	VulnerabilityID  string
	PkgName          string
	PkgPath          string
	InstalledVersion string
	FixedVersion     string
	Status           string
	Severity         string
	SeveritySource   string
	PrimaryURL       string
	Title            string
	Description      string
	PublishedDate    string
	CweIDs           []string
	References       []string
	PkgIdentifier    *struct{ PURL, UID string }
	DataSource       *struct{ ID, Name, URL string }
	VendorSeverity   map[string]int
	CVSS             map[string]trivyCVSS
}

type trivyMisconf struct {
	ID            string
	AVDID         string
	Type          string
	Title         string
	Description   string
	Message       string
	Resolution    string
	Severity      string
	Status        string
	PrimaryURL    string
	References    []string
	CauseMetadata *struct {
		StartLine int
		EndLine   int
	}
}

type trivySecret struct {
	RuleID    string
	Category  string
	Severity  string
	Title     string
	StartLine int
	Match     string
}

type trivyLicense struct {
	Severity   string
	Category   string
	PkgName    string
	FilePath   string
	Name       string
	Confidence float64
	Link       string
}

// --- native conversion ------------------------------------------------------

func convertNative(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	var report trivyReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("trivy: parsing native JSON: %w", err)
	}
	startTime := hdfutil.ParseTimestamp(report.CreatedAt)

	var requirements []hdf.EvaluatedRequirement
	for i := range report.Results {
		res := report.Results[i]
		for _, raw := range res.Vulnerabilities {
			if req, ok := convertVuln(raw, res, startTime); ok {
				requirements = append(requirements, req)
			}
		}
		for _, raw := range res.Misconfigurations {
			if req, ok := convertMisconf(raw, res, startTime); ok {
				requirements = append(requirements, req)
			}
		}
		for _, raw := range res.Secrets {
			if req, ok := convertSecret(raw, res, startTime); ok {
				requirements = append(requirements, req)
			}
		}
		for _, raw := range res.Licenses {
			if req, ok := convertLicense(raw, res, startTime); ok {
				requirements = append(requirements, req)
			}
		}
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"trivy-no-findings",
				fmt.Sprintf("Trivy scanned %s and reported zero findings.", report.ArtifactName),
				startTime,
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            baselineName,
		Requirements:    requirements,
		ResultsChecksum: shared.InputChecksum(input),
	}
	if report.ArtifactName != "" {
		baseline.Title = hdfutil.Ptr(report.ArtifactName)
	}

	var components []hdf.Component
	if c, ok := buildComponent(report); ok {
		components = []hdf.Component{c}
	}

	var timestamp *time.Time
	if !startTime.IsZero() {
		timestamp = &startTime
	}
	toolVersion := ""
	if report.Trivy != nil {
		toolVersion = report.Trivy.Version
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "trivy-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Trivy",
		ToolVersion:      toolVersion,
		Baselines:        []hdf.EvaluatedBaseline{baseline},
		Components:       components,
		Timestamp:        timestamp,
	}), nil
}

func convertVuln(raw json.RawMessage, res trivyResult, startTime time.Time) (hdf.EvaluatedRequirement, bool) {
	var v trivyVuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return hdf.EvaluatedRequirement{}, false
	}

	descriptions := []hdf.Description{{Label: "default", Data: firstNonEmpty(v.Description, v.Title, v.VulnerabilityID)}}
	if v.FixedVersion != "" {
		descriptions = append(descriptions, hdf.Description{Label: "fix", Data: fmt.Sprintf("Fixed in version %s.", v.FixedVersion)})
	}

	extras := map[string]interface{}{"class": res.Class}
	putIf(extras, "trivy_type", res.Type)
	putIf(extras, "severity_source", v.SeveritySource)
	if v.DataSource != nil {
		putIf(extras, "data_source", v.DataSource.Name)
	}
	putIf(extras, "published_date", v.PublishedDate)
	if len(v.VendorSeverity) > 0 {
		extras["vendor_severity"] = v.VendorSeverity
	}
	tags := buildTags(extras)

	req := hdf.EvaluatedRequirement{
		ID:                 "Trivy/" + v.VulnerabilityID,
		Title:              hdfutil.Ptr(fmt.Sprintf("Trivy found %s in %s", v.VulnerabilityID, pkgLabel(v.PkgName, v.InstalledVersion))),
		Descriptions:       descriptions,
		Impact:             hdfutil.SeverityToImpactWithAliases(strings.ToLower(v.Severity), severityAliases, 0.5),
		Tags:               tags,
		Cwe:                filterCWEs(v.CweIDs),
		Cvss:               buildCvssEntries(v.CVSS),
		Refs:               buildRefs(prepend(v.PrimaryURL, v.References)),
		Code:               hdfutil.Ptr(indentRaw(raw)),
		ControlType:        shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
		VerificationMethod: automated(),
		Results: []hdf.RequirementResult{{
			Status:    hdf.Failed,
			CodeDesc:  buildVulnCodeDesc(v, res),
			StartTime: startTime,
			Message:   hdfutil.Ptr(fmt.Sprintf("Severity: %s", firstNonEmpty(v.Severity, "UNKNOWN"))),
		}},
	}
	// Emit affectedPackages only when it satisfies the schema anyOf. Trivy's
	// package identity comes from the PURL (which also yields the ecosystem);
	// a name/version without a PURL lacks the required ecosystem and would be
	// schema-invalid, so gate on the PURL.
	if ap := buildAffectedPackage(v); ap.Purl != nil {
		req.AffectedPackages = []hdf.AffectedPackage{ap}
	}
	if v.PkgPath != "" {
		req.SourceLocation = &hdf.SourceLocation{Ref: hdfutil.Ptr(v.PkgPath)}
	}
	return req, true
}

func convertMisconf(raw json.RawMessage, res trivyResult, startTime time.Time) (hdf.EvaluatedRequirement, bool) {
	var m trivyMisconf
	if err := json.Unmarshal(raw, &m); err != nil {
		return hdf.EvaluatedRequirement{}, false
	}

	descriptions := []hdf.Description{{Label: "default", Data: firstNonEmpty(m.Description, m.Message, m.Title)}}
	if m.Resolution != "" {
		descriptions = append(descriptions, hdf.Description{Label: "fix", Data: m.Resolution})
	}

	extras := map[string]interface{}{}
	putIf(extras, "misconfig_type", m.Type)
	tags := buildTags(withClass(res.Class, extras))
	req := hdf.EvaluatedRequirement{
		ID:                 "Trivy/" + firstNonEmpty(m.ID, m.AVDID),
		Title:              hdfutil.Ptr(m.Title),
		Descriptions:       descriptions,
		Impact:             hdfutil.SeverityToImpactWithAliases(strings.ToLower(m.Severity), severityAliases, 0.5),
		Tags:               tags,
		Refs:               buildRefs(prepend(m.PrimaryURL, m.References)),
		Code:               hdfutil.Ptr(indentRaw(raw)),
		ControlType:        shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
		VerificationMethod: automated(),
		Results: []hdf.RequirementResult{{
			Status:    misconfStatus(m.Status),
			CodeDesc:  firstNonEmpty(m.Message, m.Title),
			StartTime: startTime,
		}},
	}
	if res.Target != "" {
		sl := &hdf.SourceLocation{Ref: hdfutil.Ptr(res.Target)}
		if m.CauseMetadata != nil && m.CauseMetadata.StartLine > 0 {
			line := float64(m.CauseMetadata.StartLine)
			sl.Line = &line
		}
		req.SourceLocation = sl
	}
	return req, true
}

func convertSecret(raw json.RawMessage, res trivyResult, startTime time.Time) (hdf.EvaluatedRequirement, bool) {
	var s trivySecret
	if err := json.Unmarshal(raw, &s); err != nil {
		return hdf.EvaluatedRequirement{}, false
	}
	tags := buildTags(withClass(res.Class, map[string]interface{}{"secret_category": s.Category}))
	req := hdf.EvaluatedRequirement{
		ID:                 fmt.Sprintf("Trivy/secret/%s@%s:%d", s.RuleID, res.Target, s.StartLine),
		Title:              hdfutil.Ptr(s.Title),
		Descriptions:       []hdf.Description{{Label: "default", Data: fmt.Sprintf("%s detected in %s (value redacted by Trivy).", firstNonEmpty(s.Title, s.RuleID), res.Target)}},
		Impact:             hdfutil.SeverityToImpactWithAliases(strings.ToLower(s.Severity), severityAliases, 0.5),
		Tags:               tags,
		Code:               hdfutil.Ptr(indentRaw(raw)),
		ControlType:        shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
		VerificationMethod: automated(),
		Results: []hdf.RequirementResult{{
			Status:    hdf.Failed,
			CodeDesc:  s.Match,
			StartTime: startTime,
		}},
	}
	if res.Target != "" {
		sl := &hdf.SourceLocation{Ref: hdfutil.Ptr(res.Target)}
		if s.StartLine > 0 {
			line := float64(s.StartLine)
			sl.Line = &line
		}
		req.SourceLocation = sl
	}
	return req, true
}

func convertLicense(raw json.RawMessage, res trivyResult, startTime time.Time) (hdf.EvaluatedRequirement, bool) {
	var l trivyLicense
	if err := json.Unmarshal(raw, &l); err != nil {
		return hdf.EvaluatedRequirement{}, false
	}
	extras := map[string]interface{}{"class": res.Class}
	putIf(extras, "license_category", l.Category)
	putIf(extras, "package", l.PkgName)
	if l.Confidence > 0 {
		extras["confidence"] = l.Confidence
	}
	tags := buildTags(extras)

	// No affectedPackages: a license finding carries only the package name, and
	// AffectedPackage requires name+version+ecosystem, a purl, or a cpe. The
	// package stays in the title/description/tags.
	req := hdf.EvaluatedRequirement{
		ID:                 fmt.Sprintf("Trivy/license/%s/%s", l.PkgName, l.Name),
		Title:              hdfutil.Ptr(fmt.Sprintf("%s (%s)", l.Name, l.Category)),
		Descriptions:       []hdf.Description{{Label: "default", Data: fmt.Sprintf("Package %s uses the %s license (category: %s).", l.PkgName, l.Name, l.Category)}},
		Impact:             hdfutil.SeverityToImpactWithAliases(strings.ToLower(l.Severity), severityAliases, 0.5),
		Tags:               tags,
		Refs:               buildRefs([]string{l.Link}),
		Code:               hdfutil.Ptr(indentRaw(raw)),
		ControlType:        shared.DeriveControlTypeFromTags(shared.NISTTagsFromMap(tags)),
		VerificationMethod: automated(),
		Results: []hdf.RequirementResult{{
			Status:    hdf.Failed,
			CodeDesc:  fmt.Sprintf("%s: %s license", l.PkgName, l.Name),
			StartTime: startTime,
		}},
	}
	if l.FilePath != "" {
		req.SourceLocation = &hdf.SourceLocation{Ref: hdfutil.Ptr(l.FilePath)}
	}
	return req, true
}

// --- component --------------------------------------------------------------

func buildComponent(report trivyReport) (hdf.Component, bool) {
	if report.ArtifactName == "" {
		return hdf.Component{}, false
	}
	if report.ArtifactType != "container_image" {
		return hdf.Component{Name: report.ArtifactName, Type: hdf.Artifact}, true
	}

	c := hdf.Component{Name: report.ArtifactName, Type: hdf.ContainerImage}
	md := report.Metadata
	if md == nil {
		return c, true
	}
	if md.ImageID != "" {
		c.ImageID = hdfutil.Ptr(md.ImageID)
	}
	if md.OS != nil {
		if md.OS.Family != "" {
			c.OSName = hdfutil.Ptr(md.OS.Family)
		}
		if md.OS.Name != "" {
			c.OSVersion = hdfutil.Ptr(md.OS.Name)
		}
	}
	if len(md.RepoDigests) > 0 {
		c.Image = hdfutil.Ptr(md.RepoDigests[0])
		c.Integrity = shared.DigestToChecksums(digestPart(md.RepoDigests[0]))
	}
	if arch := architecture(md.ImageConfig); arch != "" {
		c.Labels = map[string]string{"architecture": arch}
	}
	return c, true
}

// --- helpers ----------------------------------------------------------------

func buildTags(extras map[string]interface{}) map[string]interface{} {
	return shared.BuildNISTCCITagsWithExtras(shared.DefaultStaticAnalysisNIST, staticCCI, extras)
}

func withClass(class string, extras map[string]interface{}) map[string]interface{} {
	extras["class"] = class
	return extras
}

func automated() *hdf.VerificationMethodEnum {
	v := hdf.VerificationMethodEnumAutomated
	return &v
}

func misconfStatus(status string) hdf.ResultStatus {
	switch strings.ToUpper(status) {
	case "PASS":
		return hdf.Passed
	case "EXCEPTION":
		return hdf.NotApplicable
	default:
		return hdf.Failed
	}
}

func filterCWEs(in []string) []string {
	var out []string
	for _, c := range in {
		if cweIDPattern.MatchString(c) {
			out = append(out, c)
		}
	}
	return out
}

func buildCvssEntries(m map[string]trivyCVSS) []hdf.Cvss {
	if len(m) == 0 {
		return nil
	}
	sources := make([]string, 0, len(m))
	for s := range m {
		sources = append(sources, s)
	}
	sort.Strings(sources)

	var out []hdf.Cvss
	for _, src := range sources {
		c := m[src]
		if c.V2Vector != "" || c.V2Score != nil {
			out = append(out, shared.BuildCvss(shared.CvssInput{Version: hdf.The20, BaseVector: c.V2Vector, BaseScore: c.V2Score, Source: src}))
		}
		if c.V3Vector != "" || c.V3Score != nil {
			out = append(out, shared.BuildCvss(shared.CvssInput{Version: shared.CvssVersionFromVector(c.V3Vector, hdf.The31), BaseVector: c.V3Vector, BaseScore: c.V3Score, Source: src}))
		}
		if c.V40Vector != "" || c.V40Score != nil {
			out = append(out, shared.BuildCvss(shared.CvssInput{Version: hdf.The40, BaseVector: c.V40Vector, BaseScore: c.V40Score, Source: src}))
		}
	}
	return out
}

func buildAffectedPackage(v trivyVuln) hdf.AffectedPackage {
	ap := hdf.AffectedPackage{}
	if v.PkgName != "" {
		ap.Name = hdfutil.Ptr(v.PkgName)
	}
	if v.InstalledVersion != "" {
		ap.Version = hdfutil.Ptr(v.InstalledVersion)
	}
	if v.FixedVersion != "" {
		ap.FixedInVersion = hdfutil.Ptr(v.FixedVersion)
	}
	if v.PkgIdentifier != nil && v.PkgIdentifier.PURL != "" {
		ap.Purl = hdfutil.Ptr(v.PkgIdentifier.PURL)
		if eco := ecosystemFromPURL(v.PkgIdentifier.PURL); eco != "" {
			ap.Ecosystem = &eco
		}
	}
	return ap
}

var purlEcosystems = map[string]hdf.Ecosystem{
	"deb": hdf.Deb, "rpm": hdf.RPM, "maven": hdf.Maven, "npm": hdf.Npm,
	"pypi": hdf.Pypi, "gem": hdf.Gem, "cargo": hdf.Cargo, "golang": hdf.Go,
	"nuget": hdf.Nuget,
}

func ecosystemFromPURL(purl string) hdf.Ecosystem {
	rest := strings.TrimPrefix(purl, "pkg:")
	typ := rest
	if i := strings.IndexAny(rest, "/@?"); i >= 0 {
		typ = rest[:i]
	}
	if eco, ok := purlEcosystems[strings.ToLower(typ)]; ok {
		return eco
	}
	return ""
}

func buildRefs(urls []string) []hdf.Reference {
	seen := map[string]bool{}
	var refs []hdf.Reference
	for _, u := range urls {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		url := u
		refs = append(refs, hdf.Reference{URL: &url})
	}
	return refs
}

func buildVulnCodeDesc(v trivyVuln, res trivyResult) string {
	parts := []string{fmt.Sprintf("Package: %s@%s", v.PkgName, v.InstalledVersion)}
	if res.Type != "" {
		parts = append(parts, "Type: "+res.Type)
	}
	if v.PkgPath != "" {
		parts = append(parts, "Location: "+v.PkgPath)
	}
	if v.FixedVersion != "" {
		parts = append(parts, "Fixed: "+v.FixedVersion)
	}
	return strings.Join(parts, " | ")
}

func pkgLabel(name, version string) string {
	if version == "" {
		return name
	}
	return name + "@" + version
}

func indentRaw(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}

// digestPart returns the "<algo>:<hex>" digest portion of a repo digest
// reference ("name@<algo>:<hex>"), or the input unchanged when it carries no
// "@". The algorithm labeling is then handled by shared.DigestToChecksums.
func digestPart(ref string) string {
	if at := strings.LastIndexByte(ref, '@'); at >= 0 {
		return ref[at+1:]
	}
	return ref
}

func architecture(imageConfig json.RawMessage) string {
	if len(imageConfig) == 0 {
		return ""
	}
	var cfg struct{ Architecture string }
	if json.Unmarshal(imageConfig, &cfg) != nil {
		return ""
	}
	return cfg.Architecture
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func putIf(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func prepend(head string, tail []string) []string {
	return append([]string{head}, tail...)
}
