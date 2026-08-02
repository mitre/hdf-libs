package twistlock

import (
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

// TwistlockReport is the top-level Twistlock scan output structure.
// Container image scans wrap results in a "results" array; code repo
// scans omit that wrapper and return a single result object directly.
type TwistlockReport struct {
	Results    []TwistlockResult `json:"results"`
	ConsoleURL string            `json:"consoleURL"`
}

// TwistlockResult represents a single scan result (one image or repository).
type TwistlockResult struct {
	ID                        string                 `json:"id"`
	Name                      string                 `json:"name"`
	Repository                string                 `json:"repository"`
	Distro                    string                 `json:"distro"`
	DistroRelease             string                 `json:"distroRelease"`
	Collections               []string               `json:"collections"`
	Packages                  []TwistlockPackage     `json:"packages"`
	Vulnerabilities           []TwistlockVuln        `json:"vulnerabilities"`
	VulnerabilityDistribution *TwistlockDistribution `json:"vulnerabilityDistribution"`
	ComplianceDistribution    *TwistlockDistribution `json:"complianceDistribution"`
}

// TwistlockPackage represents an entry from the result-level "packages" array.
// Used to derive AffectedPackage.ecosystem because the per-vulnerability
// entries do not carry a package-type field of their own.
type TwistlockPackage struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// TwistlockVuln represents a single vulnerability entry.
type TwistlockVuln struct {
	ID               string   `json:"id"`
	CVE              string   `json:"cve"`
	Status           string   `json:"status"`
	CVSS             float64  `json:"cvss"`
	Vector           string   `json:"vector"`
	Description      string   `json:"description"`
	Severity         string   `json:"severity"`
	PackageName      string   `json:"packageName"`
	PackageVersion   string   `json:"packageVersion"`
	PackageType      string   `json:"packageType"`
	CWE              string   `json:"cwe"`
	Link             string   `json:"link"`
	FixedBy          string   `json:"fixedBy"`
	RiskFactors      []string `json:"riskFactors"`
	ImpactedVersions []string `json:"impactedVersions"`
	PublishedDate    string   `json:"publishedDate"`
	DiscoveredDate   string   `json:"discoveredDate"`
	FixDate          string   `json:"fixDate"`
	LayerTime        string   `json:"layerTime"`
}

// TwistlockDistribution holds vulnerability/compliance counts by severity.
type TwistlockDistribution struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// getImpact maps Twistlock severity strings to HDF impact values.
// Includes "important" (alias for critical) and "moderate" (alias for medium)
// which appear in some Twistlock outputs. Maps critical to 0.9 (not standard 1.0).

var twistlockAliases = map[string]float64{
	"critical":  0.9,
	"important": 0.9,
	"moderate":  0.5,
}

func getImpact(severity string) float64 {
	return hdfutil.SeverityToImpactWithAliases(severity, twistlockAliases, 0.5)
}

// buildTitle constructs the baseline title from scan result data.
// Uses collections (joined with " / ") if present, otherwise falls back
// to the repository field.
func buildTitle(result TwistlockResult) string {
	var projectName string
	switch {
	case result.Repository != "":
		projectName = result.Repository
	case len(result.Collections) > 0:
		projectName = strings.Join(result.Collections, " / ")
	default:
		projectName = "N/A"
	}
	return fmt.Sprintf("Twistlock Project: %s", projectName)
}

// buildSummary constructs the baseline summary from distribution data.
func buildSummary(result TwistlockResult) string {
	vulnTotal := "N/A"
	if result.VulnerabilityDistribution != nil {
		vulnTotal = fmt.Sprintf("%d", result.VulnerabilityDistribution.Total)
	}
	complianceTotal := "N/A"
	if result.ComplianceDistribution != nil {
		complianceTotal = fmt.Sprintf("%d", result.ComplianceDistribution.Total)
	}
	return fmt.Sprintf("Package Vulnerability Summary: %s Application Compliance Issue Total: %s",
		vulnTotal, complianceTotal)
}

// cvssVersionFromVector returns the schema CVSS Version enum corresponding to a
// vector string prefix (CVSS:2.0/, CVSS:3.0/, CVSS:3.1/, CVSS:4.0/). When the
// prefix is absent or unrecognized, defaults to "3.1" since modern Twistlock
// exclusively emits 3.x output.
func cvssVersionFromVector(vector string) hdf.Version {
	switch {
	case strings.HasPrefix(vector, "CVSS:2.0/"):
		return hdf.The20
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		return hdf.The30
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		return hdf.The40
	default:
		return hdf.The31
	}
}

// cvssSeverityFromScore converts the band string returned by
// hdfutil.CvssScoreToSeverity into the schema CVSSSeverity enum.
func cvssSeverityFromScore(score float64) *hdf.CVSSSeverity {
	band := hdfutil.CvssScoreToSeverity(score)
	var sev hdf.CVSSSeverity
	switch band {
	case "none":
		sev = hdf.None
	case "low":
		sev = hdf.CVSSSeverityLow
	case "medium":
		sev = hdf.CVSSSeverityMedium
	case "high":
		sev = hdf.CVSSSeverityHigh
	case "critical":
		sev = hdf.CVSSSeverityCritical
	default:
		return nil
	}
	return &sev
}

// buildCvss assembles a Cvss entry from the Twistlock vulnerability fields.
// Returns nil only when neither a score nor a vector is available. When the
// vendor emits a score but no vector (common in Twistlock/Prisma Cloud
// output), the Cvss entry is still emitted — the schema makes baseVector
// optional precisely so vendor-final-score data isn't dropped.
func buildCvss(vuln TwistlockVuln) *hdf.Cvss {
	if vuln.Vector == "" && vuln.CVSS == 0 {
		return nil
	}
	cv := hdf.Cvss{
		Version: cvssVersionFromVector(vuln.Vector),
	}
	if vuln.CVSS > 0 {
		score := vuln.CVSS
		cv.BaseScore = &score
	}
	if vuln.Vector != "" {
		v := vuln.Vector
		cv.BaseVector = &v
	}
	source := vuln.CVE
	if source == "" {
		source = vuln.ID
	}
	if source != "" {
		cv.Source = &source
	}
	if vuln.CVSS > 0 {
		cv.BaseSeverity = cvssSeverityFromScore(vuln.CVSS)
	}
	return &cv
}

// cwePattern matches a CWE identifier (case-insensitive prefix, capturing the
// numeric portion). Used to normalize various Twistlock spellings ("CWE-79",
// "cwe-79", "79") to the canonical "CWE-79" form.
var cwePattern = regexp.MustCompile(`(?i)cwe[-_]?(\d+)`)

// parseCwes extracts CWE identifiers from a free-form string and returns them
// in canonical "CWE-N" format. Empty input yields a nil slice (omitted from
// JSON output).
func parseCwes(raw string) []string {
	if raw == "" {
		return nil
	}
	matches := cwePattern.FindAllStringSubmatch(raw, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		id := "CWE-" + m[1]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// rhelEcosystem returns true when the distro string looks like a Red Hat / RHEL /
// CentOS / Fedora / Amazon Linux derivative.
func rhelEcosystem(distro string) bool {
	low := strings.ToLower(distro)
	for _, marker := range []string{"red hat", "rhel", "centos", "fedora", "amazon linux", "oracle linux", "rocky", "alma"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// debEcosystem returns true when the distro string looks like a Debian / Ubuntu
// derivative.
func debEcosystem(distro string) bool {
	low := strings.ToLower(distro)
	for _, marker := range []string{"debian", "ubuntu"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

// resolveEcosystem maps a Twistlock package type plus the result's distro to a
// schema Ecosystem value. Defaults to "generic" when the type is unknown.
func resolveEcosystem(packageType, distro string) hdf.Ecosystem {
	switch strings.ToLower(packageType) {
	case "os":
		switch {
		case rhelEcosystem(distro):
			return hdf.RPM
		case debEcosystem(distro):
			return hdf.Deb
		default:
			return hdf.Generic
		}
	case "rpm":
		return hdf.RPM
	case "deb":
		return hdf.Deb
	case "jar", "maven":
		return hdf.Maven
	case "python", "pypi":
		return hdf.Pypi
	case "nodejs", "npm":
		return hdf.Npm
	case "gem":
		return hdf.Gem
	case "nuget":
		return hdf.Nuget
	case "go":
		return hdf.Go
	case "cargo":
		return hdf.Cargo
	default:
		return hdf.Generic
	}
}

// fixVersionRegex extracts the first version-looking token from a status string
// such as "fixed in 2.15.0, 2.12.2".
var fixVersionRegex = regexp.MustCompile(`\d+(\.\d+)+[A-Za-z0-9._+\-]*`)

// extractFixedInVersion pulls the first version token from explicit fixedBy
// field, falling back to status when the status indicates a fix is available.
func extractFixedInVersion(vuln TwistlockVuln) string {
	if vuln.FixedBy != "" {
		return vuln.FixedBy
	}
	status := strings.ToLower(vuln.Status)
	if !strings.Contains(status, "fixed") {
		return ""
	}
	if m := fixVersionRegex.FindString(vuln.Status); m != "" {
		return m
	}
	return ""
}

// buildAffectedPackage constructs an AffectedPackage from the per-vulnerability
// fields plus a lookup of result-level package types. Returns nil when there is
// no package name + version pair (the two required AffectedPackage fields).
func buildAffectedPackage(vuln TwistlockVuln, packageTypes map[string]string, distro string) *hdf.AffectedPackage {
	if vuln.PackageName == "" || vuln.PackageVersion == "" {
		return nil
	}
	pkgType := vuln.PackageType
	if pkgType == "" {
		pkgType = packageTypes[vuln.PackageName]
	}
	name := vuln.PackageName
	version := vuln.PackageVersion
	ecosystem := resolveEcosystem(pkgType, distro)
	pkg := hdf.AffectedPackage{
		Name:      &name,
		Version:   &version,
		Ecosystem: &ecosystem,
	}
	if fixed := extractFixedInVersion(vuln); fixed != "" {
		pkg.FixedInVersion = &fixed
	}
	return &pkg
}

// buildPackageTypeIndex collects package name → type mappings from the
// result-level "packages" array. Used to resolve ecosystem for per-vuln
// findings that lack their own packageType field.
func buildPackageTypeIndex(pkgs []TwistlockPackage) map[string]string {
	idx := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" || p.Type == "" {
			continue
		}
		idx[p.Name] = p.Type
	}
	return idx
}

// formatCodeDesc builds the code_desc string for a vulnerability result.
func formatCodeDesc(vuln TwistlockVuln) string {
	packageName := vuln.PackageName
	if packageName == "" {
		packageName = "N/A"
	}
	impactedVersions := "N/A"
	if len(vuln.ImpactedVersions) > 0 {
		impactedVersions = "[" + strings.Join(vuln.ImpactedVersions, " ") + "]"
	}
	return fmt.Sprintf("Package %q should be updated to latest version above impacted versions %s",
		packageName, impactedVersions)
}

// buildRequirement converts a single vulnerability into an EvaluatedRequirement.
// The packageTypes map and distro provide context for resolving the package
// ecosystem when the per-vulnerability entry doesn't include packageType.
func buildRequirement(vuln TwistlockVuln, packageTypes map[string]string, distro string) hdf.EvaluatedRequirement {
	nist := shared.DefaultRemediationNIST
	cciTags := cci.NISTToCCI(nist)

	extras := map[string]interface{}{
		"cveid": []interface{}{vuln.ID},
	}
	// Legacy: retain the cvss_base_score tag for one release so existing
	// downstream queries keep working. Marked for removal in v3.4.0 (see
	// CHANGELOG note in epic hdf-libs-8zn0).
	if vuln.CVSS > 0 {
		extras["cvss_base_score"] = vuln.CVSS
	}
	tags := shared.BuildNISTCCITagsWithExtras(nist, cciTags, extras)

	descriptions := []hdf.Description{
		{Label: "default", Data: vuln.Description},
	}

	startTime := hdfutil.ParseTimestamp(vuln.DiscoveredDate)

	results := []hdf.RequirementResult{
		{
			Status:    hdf.Failed,
			CodeDesc:  formatCodeDesc(vuln),
			StartTime: startTime,
		},
	}

	title := vuln.ID
	req := hdf.EvaluatedRequirement{
		ID:                 vuln.ID,
		Title:              &title,
		Impact:             getImpact(vuln.Severity),
		Tags:               tags,
		ControlType:        shared.DeriveControlTypeFromTags(nist),
		Descriptions:       descriptions,
		Results:            results,
		VerificationMethod: hdfutil.Ptr(hdf.VerificationMethodEnumAutomated),
	}

	if cv := buildCvss(vuln); cv != nil {
		req.Cvss = []hdf.Cvss{*cv}
	}
	if cwes := parseCwes(vuln.CWE); len(cwes) > 0 {
		req.Cwe = cwes
	}
	if pkg := buildAffectedPackage(vuln, packageTypes, distro); pkg != nil {
		req.AffectedPackages = []hdf.AffectedPackage{*pkg}
	}

	return req
}

// resultTarget returns a human-readable identifier for a result, used in
// the synthesized no-findings codeDesc and (indirectly) elsewhere.
func resultTarget(result TwistlockResult) string {
	switch {
	case result.Name != "":
		return result.Name
	case result.Repository != "":
		return result.Repository
	case result.ID != "":
		return result.ID
	default:
		return "scan target"
	}
}

// convertSingleResult converts one TwistlockResult to an EvaluatedBaseline.
func convertSingleResult(result TwistlockResult, checksum *hdf.Checksum) hdf.EvaluatedBaseline {
	vulns := result.Vulnerabilities
	if vulns == nil {
		vulns = []TwistlockVuln{}
	}

	limitedVulns := shared.LimitSliceWithWarning(vulns, 0, "vulnerability")

	packageTypes := buildPackageTypeIndex(result.Packages)

	requirements := make([]hdf.EvaluatedRequirement, len(limitedVulns))
	for i, vuln := range limitedVulns {
		requirements[i] = buildRequirement(vuln, packageTypes, result.Distro)
	}

	if len(requirements) == 0 {
		requirements = []hdf.EvaluatedRequirement{
			shared.BuildNoFindingsRequirement(
				"twistlock-no-findings",
				fmt.Sprintf("Twistlock scanned %s and reported zero vulnerable components.", resultTarget(result)),
				time.Now().UTC(),
			),
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            "Twistlock Scan",
		Requirements:    requirements,
		ResultsChecksum: checksum,
	}

	title := buildTitle(result)
	baseline.Title = &title

	summary := buildSummary(result)
	baseline.Summary = &summary

	return baseline
}

// ConvertTwistlockToHDF converts Twistlock/Prisma Cloud scan output to HDF format.
// Handles both container image scans (with "results" wrapper) and code repository
// scans (single result object without wrapper).
func ConvertTwistlockToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("twistlock: empty input")
	}
	if err := shared.ValidateJSONSize(input, "twistlock", 0); err != nil {
		return nil, fmt.Errorf("twistlock: %w", err)
	}

	checksum := shared.InputChecksum(input)

	// Try parsing as wrapped report (has "results" key)
	var report TwistlockReport
	if err := json.Unmarshal(input, &report); err != nil {
		return nil, fmt.Errorf("twistlock: invalid JSON: %w", err)
	}

	// If no results array found, this might be a code repo scan (unwrapped single result)
	if report.Results == nil {
		var singleResult TwistlockResult
		if err := json.Unmarshal(input, &singleResult); err != nil {
			return nil, fmt.Errorf("twistlock: invalid JSON: %w", err)
		}
		report.Results = []TwistlockResult{singleResult}
	}

	if len(report.Results) == 0 {
		return nil, fmt.Errorf("twistlock: no scan results found")
	}

	baselines := make([]hdf.EvaluatedBaseline, len(report.Results))
	for i, result := range report.Results {
		baselines[i] = convertSingleResult(result, checksum)
	}

	// Use the first result's name or repository as target name
	targetName := report.Results[0].Name
	if targetName == "" {
		targetName = report.Results[0].Repository
	}

	now := time.Now().UTC()

	// Code-repo scans carry no image id, so there is no image label to attach.
	component := hdf.Component{Name: targetName, Type: hdf.ContainerImage}
	if imageID := report.Results[0].ID; imageID != "" {
		component.Labels = map[string]string{"image": imageID}
	}

	return shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "twistlock-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Twistlock",
		Baselines:        baselines,
		Components:       []hdf.Component{component},
		Timestamp:        &now,
	}), nil
}
