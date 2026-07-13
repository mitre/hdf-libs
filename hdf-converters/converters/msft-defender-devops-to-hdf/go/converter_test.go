package msftdefenderdevops

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

// ---- Empty-baseline placeholder synthesis (issue #80 bug 3) ----

func TestConvert_SynthesizesPlaceholderForEmptyBaselines(t *testing.T) {
	input := loadFixture(t, "input/sda.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// Baselines 0/1/3 (antimalware/bandit/eslint) are runs whose SARIF
	// results array is empty — per SARIF v2.1.0 §3.7.2 that signals
	// "analysis completed, no findings." The converter must emit a single
	// `passed` placeholder requirement so the baseline satisfies the HDF
	// schema's requirements.minItems=1 invariant.
	emptyBaselineIdxs := []int{0, 1, 3}
	emptyBaselineNames := []string{"antimalware", "bandit", "eslint"}

	for k, idx := range emptyBaselineIdxs {
		baseline := result.Baselines[idx]
		tool := emptyBaselineNames[k]
		require.Equal(t, tool, baseline.Name)
		require.Len(t, baseline.Requirements, 1,
			"empty baseline %q should have one synthesized placeholder", tool)

		req := baseline.Requirements[0]
		assert.Equal(t, tool+"-no-findings", req.ID)
		require.Len(t, req.Descriptions, 1)
		assert.Equal(t, "default", req.Descriptions[0].Label)
		assert.Contains(t, req.Descriptions[0].Data, tool)

		require.Len(t, req.Results, 1)
		assert.Equal(t, hdf.Passed, req.Results[0].Status,
			"per SARIF/XCCDF/NIST 800-53A semantics, 'tool ran clean' is passed, not notApplicable")
		assert.Contains(t, req.Results[0].CodeDesc, tool)
		assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
		require.NotNil(t, result.Timestamp)
		assert.Equal(t, *result.Timestamp, req.Results[0].StartTime,
			"synthesized startTime should equal the doc-level Timestamp")

		// applyEnrichments runs after synthesis, so per-run MSDO tags
		// (organization/product/etc.) should also land on the synthesized
		// requirement when the SARIF run carries them.
		assert.NotNil(t, req.Tags, "synthesized requirement should still be enriched with run tags")
	}

	// Non-empty baselines should be untouched (no synthesized placeholder injected).
	credscan := result.Baselines[2]
	assert.Equal(t, "credscan", credscan.Name)
	require.NotEmpty(t, credscan.Requirements)
	assert.NotEqual(t, "credscan-no-findings", credscan.Requirements[0].ID,
		"credscan has real findings; the synthesis pass must not inject a placeholder")
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
		return ConvertMsftDefenderDevopsToHDF(input, "1.0.0")
	})
}

func TestConvert_ControlType(t *testing.T) {
	input := loadFixture(t, "input/sda.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)

	// MSDO delegates to SARIF, which derives controlType from NIST tags
	// resolved via CWE mapping. The sda.sarif fixture is a multi-tool SARIF
	// log: some baselines are empty, others carry findings. At least one
	// requirement across all baselines should have a derived controlType.
	var sawDerivation bool
	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			if req.ControlType != nil {
				sawDerivation = true
				switch *req.ControlType {
				case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
				default:
					t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
				}
			}
		}
	}
	assert.False(t, sawDerivation, "converter uses static-fallback NIST only; controlType must be omitted per helper gate")
}

func TestConvertMsftDefenderDevops_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.sarif")
	result, err := ConvertMsftDefenderDevopsToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	var seenAny bool
	for _, b := range result.Baselines {
		for _, req := range b.Requirements {
			seenAny = true
			require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
			assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
				"requirement %q: MSDO delegates to SARIF — automated scanner output", req.ID)
		}
	}
	assert.True(t, seenAny, "expected at least one requirement across all baselines")
}
