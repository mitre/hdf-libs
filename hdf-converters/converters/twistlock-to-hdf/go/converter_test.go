package twistlock

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "twistlock-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertTwistlockToHDF(input, testVersion) },
		MinimalFixture: "twistlock-twistcli-coderepo-scan-sample.json",
	})
}

// ---- Container scan (has "results" wrapper) ----

func TestConvertTwistlock_ContainerScan_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	// sample-1 has 1 result in the "results" array → 1 baseline
	require.Len(t, result.Baselines, 1)
}

func TestConvertTwistlock_ContainerScan_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Twistlock Scan", result.Baselines[0].Name)
}

func TestConvertTwistlock_ContainerScan_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	// Title should contain "Twistlock Project:" and collections info
	assert.Contains(t, *result.Baselines[0].Title, "Twistlock Project:")
}

func TestConvertTwistlock_ContainerScan_Summary(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Summary)
	assert.Contains(t, *result.Baselines[0].Summary, "Package Vulnerability Summary:")
}

func TestConvertTwistlock_ContainerScan_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	// sample-1 result[0] has 97 vulnerabilities, each with unique CVE ID
	assert.Len(t, result.Baselines[0].Requirements, 97)
}

func TestConvertTwistlock_ContainerScan_Checksum(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Code repo scan (no "results" wrapper) ----

func TestConvertTwistlock_CodeRepoScan_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	// coderepo scan has no "results" wrapper → auto-wrapped to 1 baseline
	require.Len(t, result.Baselines, 1)
}

func TestConvertTwistlock_CodeRepoScan_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	// Should contain repository name "My-Repo"
	assert.Contains(t, *result.Baselines[0].Title, "My-Repo")
}

func TestConvertTwistlock_CodeRepoScan_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	// coderepo has 4 CVEs, all unique
	assert.Len(t, result.Baselines[0].Requirements, 4)
}

// ---- Generator ----

func TestConvertTwistlock_Generator(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "twistlock-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertTwistlock_Tool(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Twistlock", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "JSON", *result.Tool.Format)
}

// ---- Severity → Impact mapping ----

func TestConvertTwistlock_SeverityMapping(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// critical → 0.9 (CVE-2021-44228)
	critical := shared.MustFindRequirement(t, reqs, "CVE-2021-44228")
	assert.InDelta(t, 0.9, critical.Impact, 0.001)

	// high → 0.7 (CVE-2021-45105)
	high := shared.MustFindRequirement(t, reqs, "CVE-2021-45105")
	assert.InDelta(t, 0.7, high.Impact, 0.001)

	// medium → 0.5 (CVE-2021-44832)
	medium := shared.MustFindRequirement(t, reqs, "CVE-2021-44832")
	assert.InDelta(t, 0.5, medium.Impact, 0.001)
}

func TestSeverityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 0.9},
		{"CRITICAL", 0.9},
		{"important", 0.9},
		{"high", 0.7},
		{"HIGH", 0.7},
		{"medium", 0.5},
		{"MEDIUM", 0.5},
		{"moderate", 0.5},
		{"low", 0.3},
		{"LOW", 0.3},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

// ---- Tags: NIST and CCI ----

func TestConvertTwistlock_DefaultNISTTags(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-44228")

	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	// Should use DefaultRemediationNIST since Twistlock doesn't provide CWE
	assert.Contains(t, nist, "SI-2")
	assert.Contains(t, nist, "RA-5")
}

func TestConvertTwistlock_CVEIDTag(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-44228")

	cveid := hdfutil.SafeStringSlice(req.Tags["cveid"])
	require.NotNil(t, cveid)
	assert.Contains(t, cveid, "CVE-2021-44228")
}

// ---- All results should be Failed ----

func TestConvertTwistlock_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all Twistlock vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- Code description ----

func TestConvertTwistlock_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-44228")
	require.NotEmpty(t, req.Results)

	// code_desc includes package name and impacted versions
	assert.Contains(t, req.Results[0].CodeDesc, "org.apache.logging.log4j_log4j-core")
}

// ---- Default description ----

func TestConvertTwistlock_Description(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-44228")

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.Contains(t, desc.Data, "Log4j")
}

// ---- Requirement title and ID ----

func TestConvertTwistlock_RequirementTitleAndID(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-44228")
	assert.Equal(t, "CVE-2021-44228", req.ID)
	require.NotNil(t, req.Title)
	assert.Equal(t, "CVE-2021-44228", *req.Title)
}

// ---- Target ----

func TestConvertTwistlock_Target(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	// Target name should be the image name
	assert.Contains(t, result.Components[0].Name, "registry.io/test")
	assert.Equal(t, hdf.ContainerImage, result.Components[0].Type)
}

// ---- Empty vulnerabilities ----

func TestConvertTwistlock_EmptyVulnerabilities(t *testing.T) {
	input := []byte(`{
		"results": [{
			"name": "clean-image",
			"collections": ["All"],
			"vulnerabilities": null,
			"vulnerabilityDistribution": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
			"complianceDistribution": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
		}]
	}`)
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "twistlock-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Twistlock")
	assert.Contains(t, req.Results[0].CodeDesc, "vulnerable components")
	assert.Contains(t, req.Results[0].CodeDesc, "clean-image")
}

func TestConvertTwistlock_NoFindingsFixture(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "twistlock-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Twistlock")
	assert.Contains(t, req.Results[0].CodeDesc, "vulnerable components")
	assert.Contains(t, req.Results[0].CodeDesc, "registry.io/clean:latest")
	assert.InDelta(t, 0.0, req.Impact, 0.001)
}

func TestConvertTwistlock_NoFindingsMultiResult(t *testing.T) {
	// Each result becomes its own baseline; clean baselines must still
	// satisfy requirements.minItems=1 individually.
	input := []byte(`{
		"results": [
			{"name": "image-a", "vulnerabilities": []},
			{"name": "image-b", "vulnerabilities": []}
		]
	}`)
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 2)
	for i, b := range result.Baselines {
		require.Lenf(t, b.Requirements, 1, "baseline %d should have synthesized requirement", i)
		assert.Equal(t, "twistlock-no-findings", b.Requirements[0].ID)
	}
	assert.Contains(t, result.Baselines[0].Requirements[0].Results[0].CodeDesc, "image-a")
	assert.Contains(t, result.Baselines[1].Requirements[0].Results[0].CodeDesc, "image-b")
}

// ---- Start time from discoveredDate ----

func TestConvertTwistlock_StartTime(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "CVE-2021-44228")
	require.NotEmpty(t, req.Results)

	expected, err := time.Parse(time.RFC3339, "2021-12-10T10:15:00Z")
	require.NoError(t, err)
	assert.Equal(t, expected, req.Results[0].StartTime)
}

func TestConvertTwistlock_ControlType(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.False(t, sawDerivation, "converter uses static-fallback NIST only; controlType must be omitted per helper gate")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "twistlock-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertTwistlockToHDF(input, "1.0.0")
	})
}

// ---- Structured CVE-ecosystem fields (cvss[], cwe[], affectedPackages[]) ----

func TestConvertTwistlock_CvssPopulated_CodeRepo(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2021-44228")
	require.Len(t, req.Cvss, 1, "expected a single cvss entry")
	cv := req.Cvss[0]
	assert.Equal(t, hdf.The31, cv.Version)
	require.NotNil(t, cv.BaseVector)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", *cv.BaseVector)
	require.NotNil(t, cv.BaseScore)
	assert.InDelta(t, 10.0, *cv.BaseScore, 0.001)
	require.NotNil(t, cv.BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityCritical, *cv.BaseSeverity)
	require.NotNil(t, cv.Source)
	assert.Equal(t, "CVE-2021-44228", *cv.Source)
}

func TestConvertTwistlock_CvssVersionDetect(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   hdf.Version
	}{
		{"v3.1 prefix", "CVSS:3.1/AV:N", hdf.The31},
		{"v3.0 prefix", "CVSS:3.0/AV:N", hdf.The30},
		{"v4.0 prefix", "CVSS:4.0/AV:N", hdf.The40},
		{"v2.0 prefix", "CVSS:2.0/AV:N", hdf.The20},
		{"no prefix defaults to 3.1", "AV:N/AC:L", hdf.The31},
		{"empty defaults to 3.1", "", hdf.The31},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, cvssVersionFromVector(tc.vector))
		})
	}
}

func TestConvertTwistlock_CvssSeverityBands(t *testing.T) {
	tests := []struct {
		score float64
		want  hdf.CVSSSeverity
	}{
		{0.0, hdf.None},
		{0.1, hdf.CVSSSeverityLow},
		{3.9, hdf.CVSSSeverityLow},
		{4.0, hdf.CVSSSeverityMedium},
		{6.9, hdf.CVSSSeverityMedium},
		{7.0, hdf.CVSSSeverityHigh},
		{8.9, hdf.CVSSSeverityHigh},
		{9.0, hdf.CVSSSeverityCritical},
		{10.0, hdf.CVSSSeverityCritical},
	}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			got := cvssSeverityFromScore(tc.score)
			require.NotNil(t, got)
			assert.Equal(t, tc.want, *got)
		})
	}
}

func TestConvertTwistlock_CvssEmittedScoreOnlyWhenVectorAbsent(t *testing.T) {
	// When the vendor emits a score but no vector (common in Twistlock /
	// Prisma Cloud output), we still emit a Cvss entry — baseVector is
	// optional on the schema precisely so vendor-final-score data isn't
	// dropped. Cannot be recomputed by consumers, but it IS structurally
	// preserved.
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	// Synthesize a finding with neither score nor vector to exercise the
	// only path that returns nil.
	empty := TwistlockVuln{ID: "CVE-TEST", Severity: "low"}
	assert.Nil(t, buildCvss(empty))

	// CVE-2022-1650 has a score but no vector → Cvss entry is emitted with
	// baseScore + baseSeverity set, baseVector absent.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2022-1650")
	require.Len(t, req.Cvss, 1)
	require.NotNil(t, req.Cvss[0].BaseScore)
	assert.InDelta(t, 8.1, *req.Cvss[0].BaseScore, 0.001)
	assert.Nil(t, req.Cvss[0].BaseVector)
	require.NotNil(t, req.Cvss[0].BaseSeverity)
	require.NotNil(t, req.Tags)
	assert.InDelta(t, 8.1, req.Tags["cvss_base_score"], 0.001)
}

func TestConvertTwistlock_AffectedPackagesMavenEcosystem(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2021-44228")
	require.Len(t, req.AffectedPackages, 1)
	pkg := req.AffectedPackages[0]
	require.NotNil(t, pkg.Name)
	require.NotNil(t, pkg.Version)
	require.NotNil(t, pkg.Ecosystem)
	assert.Equal(t, "org.apache.logging.log4j_log4j-core", *pkg.Name)
	assert.Equal(t, "2.14.1", *pkg.Version)
	assert.Equal(t, hdf.Maven, *pkg.Ecosystem)
	require.NotNil(t, pkg.FixedInVersion)
	assert.Equal(t, "2.15.0", *pkg.FixedInVersion)
}

func TestConvertTwistlock_AffectedPackagesRpmEcosystem(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	// CVE-2021-43529 from sample-1 affects nss-util (os type → rpm via RHEL distro).
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2021-43529")
	require.Len(t, req.AffectedPackages, 1)
	pkg := req.AffectedPackages[0]
	require.NotNil(t, pkg.Name)
	require.NotNil(t, pkg.Ecosystem)
	assert.Equal(t, "nss-util", *pkg.Name)
	assert.Equal(t, hdf.RPM, *pkg.Ecosystem)
}

func TestConvertTwistlock_AffectedPackageOmittedWhenNoName(t *testing.T) {
	v := TwistlockVuln{ID: "CVE-X", Severity: "low"}
	assert.Nil(t, buildAffectedPackage(v, map[string]string{}, ""))
}

func TestConvertTwistlock_ResolveEcosystemMatrix(t *testing.T) {
	tests := []struct {
		pkgType string
		distro  string
		want    hdf.Ecosystem
	}{
		{"os", "Red Hat Enterprise Linux release 8.6 (Ootpa)", hdf.RPM},
		{"os", "Ubuntu 22.04", hdf.Deb},
		{"os", "Alpine Linux 3.18", hdf.Generic},
		{"jar", "", hdf.Maven},
		{"python", "", hdf.Pypi},
		{"nodejs", "", hdf.Npm},
		{"gem", "", hdf.Gem},
		{"nuget", "", hdf.Nuget},
		{"go", "", hdf.Go},
		{"", "", hdf.Generic},
		{"unknown-type", "", hdf.Generic},
	}
	for _, tc := range tests {
		t.Run(tc.pkgType+"/"+tc.distro, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveEcosystem(tc.pkgType, tc.distro))
		})
	}
}

func TestConvertTwistlock_FixedInVersionFromStatus(t *testing.T) {
	tests := []struct {
		name string
		vuln TwistlockVuln
		want string
	}{
		{"explicit fixedBy wins", TwistlockVuln{FixedBy: "1.2.3", Status: "fixed in 9.9.9"}, "1.2.3"},
		{"status fixed in", TwistlockVuln{Status: "fixed in 2.15.0, 2.12.2"}, "2.15.0"},
		{"status affected", TwistlockVuln{Status: "affected"}, ""},
		{"empty", TwistlockVuln{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, extractFixedInVersion(tc.vuln))
		})
	}
}

func TestConvertTwistlock_ParseCwes(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"no cwe here", nil},
		{"CWE-79", []string{"CWE-79"}},
		{"cwe-79", []string{"CWE-79"}},
		{"CWE-79 and CWE-89", []string{"CWE-79", "CWE-89"}},
		{"CWE-79, CWE-79", []string{"CWE-79"}},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, parseCwes(tc.in))
		})
	}
}

func TestConvertTwistlock_CweFromVuln(t *testing.T) {
	// Synthetic input with cwe field to exercise the populated path,
	// since real Twistlock fixtures don't include it.
	input := []byte(`{
		"results": [{
			"name": "synthetic",
			"distro": "Red Hat Enterprise Linux 8",
			"packages": [{"type": "os", "name": "openssl", "version": "1.0"}],
			"vulnerabilities": [{
				"id": "CVE-2099-0001",
				"severity": "high",
				"description": "synthetic",
				"cvss": 7.5,
				"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				"cwe": "CWE-79",
				"packageName": "openssl",
				"packageVersion": "1.0",
				"status": "fixed in 1.1"
			}]
		}]
	}`)
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2099-0001")
	assert.Equal(t, []string{"CWE-79"}, req.Cwe)
}

func TestConvertTwistlock_LegacyCvssBaseScoreTagRetained(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "CVE-2021-44228")
	// Legacy tag retained for backward compatibility (removed in v3.4.0).
	got, ok := req.Tags["cvss_base_score"]
	require.True(t, ok, "expected legacy cvss_base_score tag to remain populated")
	score, ok := got.(float64)
	require.True(t, ok, "cvss_base_score should be numeric, got %T", got)
	assert.InDelta(t, 10.0, score, 0.001)
}

func TestConvertTwistlock_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-sample-1.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}
