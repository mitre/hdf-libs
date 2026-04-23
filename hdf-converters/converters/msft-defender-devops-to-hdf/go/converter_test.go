package msftdefenderdevops

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
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

// ---- Error handling ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "msft-defender-devops-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertMsftDefenderDevopsToHDF(input, testVersion) },
		MinimalFixture: "minimal.sarif",
	})
}

// ---- Minimal fixture conversion ----

func TestConvert_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Minimal fixture has 2 runs → 2 baselines
	assert.Len(t, result.Baselines, 2)

	// First baseline (credscan) should have requirements
	assert.NotEmpty(t, result.Baselines[0].Requirements)
	// Second baseline (checkov) should have requirements
	assert.NotEmpty(t, result.Baselines[1].Requirements)
}

// ---- Full SDA fixture ----

func TestConvert_FullSDA(t *testing.T) {
	input := loadFixture(t, "input/sda.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// 7 runs → 7 baselines
	assert.Len(t, result.Baselines, 7)

	// Verify tool names are preserved from the SARIF converter
	expectedNames := []string{
		"antimalware", "bandit", "credscan", "eslint",
		"iacfilescanner", "templateanalyzer", "checkov",
	}
	for i, name := range expectedNames {
		assert.Equal(t, name, result.Baselines[i].Name,
			"baseline %d should be named %s", i, name)
	}
}

// ---- Repository target from versionControlProvenance ----

func TestConvert_RepositoryTarget(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components, "should have at least one target")
	target := result.Components[0]

	assert.Equal(t, hdf.Repository, target.Type)
	assert.Equal(t, "security-devops-action", target.Name)
	require.NotNil(t, target.URL)
	assert.Contains(t, *target.URL, "github.com")
	require.NotNil(t, target.Branch)
	assert.Equal(t, "main", *target.Branch)
	require.NotNil(t, target.Commit)
	assert.NotEmpty(t, *target.Commit)
}

func TestConvert_RepositoryTargetDeduplicated(t *testing.T) {
	input := loadFixture(t, "input/sda.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// All 7 runs reference the same repo — should deduplicate to 1 target
	assert.Len(t, result.Components, 1)
}

// ---- Tool metadata tags ----

func TestConvert_ToolMetadata(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// First baseline is credscan which has organization, product, fullName
	require.NotEmpty(t, result.Baselines[0].Requirements)
	req := result.Baselines[0].Requirements[0]

	assert.Equal(t, "Microsoft Corporation", req.Tags["msdo_organization"])
	assert.Equal(t, "Microsoft Security Credential Scanner Client", req.Tags["msdo_product"])
	assert.Equal(t, "CredentialScanner 2.5.1.13", req.Tags["msdo_fullName"])
	assert.Equal(t, "credscan", req.Tags["msdo_rawName"])
}

func TestConvert_ToolMetadataMinimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// Second baseline is checkov which has only RawName in properties
	require.NotEmpty(t, result.Baselines[1].Requirements)
	req := result.Baselines[1].Requirements[0]

	assert.Equal(t, "checkov", req.Tags["msdo_rawName"])
	// Should not have organization/product/fullName (not set for checkov)
	_, hasOrg := req.Tags["msdo_organization"]
	assert.False(t, hasOrg, "checkov should not have msdo_organization")
}

// ---- Policy tag ----

func TestConvert_PolicyTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Baselines[0].Requirements)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "Microsoft 2.0.3", req.Tags["msdo_policy"])
}

// ---- Result properties (CredScan) ----

func TestConvert_ResultProperties(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// CredScan results have DefectCode, MatchingScore, Risk, etc.
	require.NotEmpty(t, result.Baselines[0].Requirements)
	req := result.Baselines[0].Requirements[0]

	props, ok := req.Tags["msdo_properties"].(map[string]interface{})
	require.True(t, ok, "msdo_properties should be a map")
	assert.Equal(t, "SecretInFile", props["DefectCode"])
	assert.NotNil(t, props["MatchingScore"])
	assert.NotNil(t, props["Risk"])
	assert.Equal(t, "NoValidationRequested", props["Validation"])
}

// ---- Generator name ----

func TestConvert_GeneratorName(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "msft-defender-devops-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvert_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Microsoft Defender for DevOps", *result.Tool.Name)
}

// ---- Delegates base SARIF processing ----

func TestConvert_DelegatesBaseSARIF(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// Verify base SARIF conversion produces proper requirements with CWE/NIST tags
	require.NotEmpty(t, result.Baselines[1].Requirements)
	req := result.Baselines[1].Requirements[0]

	// The SARIF converter should have populated these standard tags
	assert.NotNil(t, req.Tags["nist"], "nist tag should be set by SARIF converter")
	assert.NotNil(t, req.Tags["severity"], "severity tag should be set by SARIF converter")
}

// ---- Checksum ----

func TestConvert_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Helper: repoNameFromURI ----

func TestRepoNameFromURI(t *testing.T) {
	tests := []struct {
		uri      string
		expected string
	}{
		{"https://github.com/org/repo", "repo"},
		{"https://github.com/org/repo.git", "repo.git"},
		{"https://dev.azure.com/org/project/_git/repo", "repo"},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			assert.Equal(t, tc.expected, repoNameFromURI(tc.uri))
		})
	}
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "msft-defender-devops-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertMsftDefenderDevopsToHDF(input, "0.1.0")
	})
}
