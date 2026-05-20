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

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
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
	critical := findRequirement(reqs, "CVE-2021-44228")
	require.NotNil(t, critical, "expected critical vuln CVE-2021-44228")
	assert.InDelta(t, 0.9, critical.Impact, 0.001)

	// high → 0.7 (CVE-2021-45105)
	high := findRequirement(reqs, "CVE-2021-45105")
	require.NotNil(t, high, "expected high vuln CVE-2021-45105")
	assert.InDelta(t, 0.7, high.Impact, 0.001)

	// medium → 0.5 (CVE-2021-44832)
	medium := findRequirement(reqs, "CVE-2021-44832")
	require.NotNil(t, medium, "expected medium vuln CVE-2021-44832")
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
	req := findRequirement(reqs, "CVE-2021-44228")
	require.NotNil(t, req)

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
	req := findRequirement(reqs, "CVE-2021-44228")
	require.NotNil(t, req)

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
	req := findRequirement(reqs, "CVE-2021-44228")
	require.NotNil(t, req)
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
	req := findRequirement(reqs, "CVE-2021-44228")
	require.NotNil(t, req)

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
	req := findRequirement(reqs, "CVE-2021-44228")
	require.NotNil(t, req)
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
	assert.Len(t, result.Baselines[0].Requirements, 0)
}

// ---- Start time from discoveredDate ----

func TestConvertTwistlock_StartTime(t *testing.T) {
	input := loadFixture(t, "input/twistlock-twistcli-coderepo-scan-sample.json")
	result, err := ConvertTwistlockToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirement(reqs, "CVE-2021-44228")
	require.NotNil(t, req)
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
		return ConvertTwistlockToHDF(input, "0.1.0")
	})
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
