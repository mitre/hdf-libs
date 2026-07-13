package checkov

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

// ---- Contract tests ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "checkov-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertCheckovToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

// ---- ControlType derivation ----

func TestConvertCheckovToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

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

// ---- Generator and tool metadata ----

func TestConvertCheckovToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "checkov-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

func TestConvertCheckovToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Checkov", *result.Tool.Name)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "3.2.524", *result.Tool.Version)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "terraform", *result.Tool.Format)
}

// ---- Baseline structure ----

func TestConvertCheckovToHDF_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
}

func TestConvertCheckovToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Checkov Scan", result.Baselines[0].Name)
}

func TestConvertCheckovToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Grouping by check_id ----

func TestConvertCheckovToHDF_GroupsByCheckID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	// minimal.json has CKV_TF_2 (2 passed), CKV_TF_1 (3 failed),
	// CKV2_AWS_6 (1 skipped), CKV_AWS_18 (1 skipped) → 4 unique check_ids
	reqs := result.Baselines[0].Requirements
	assert.Len(t, reqs, 4)
}

func TestConvertCheckovToHDF_MultipleResultsPerRequirement(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	var ckvTF1 *hdf.EvaluatedRequirement
	for i := range reqs {
		if reqs[i].ID == "CKV_TF_1" {
			ckvTF1 = &reqs[i]
			break
		}
	}
	require.NotNil(t, ckvTF1, "expected requirement CKV_TF_1")
	assert.Len(t, ckvTF1.Results, 3, "CKV_TF_1 should have 3 results (one per resource)")
}

// ---- Requirement fields ----

func TestConvertCheckovToHDF_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	ids := make(map[string]bool)
	for _, req := range result.Baselines[0].Requirements {
		ids[req.ID] = true
	}
	assert.True(t, ids["CKV_TF_1"], "expected requirement ID CKV_TF_1")
	assert.True(t, ids["CKV_TF_2"], "expected requirement ID CKV_TF_2")
	assert.True(t, ids["CKV2_AWS_6"], "expected requirement ID CKV2_AWS_6")
	assert.True(t, ids["CKV_AWS_18"], "expected requirement ID CKV_AWS_18")
}

func TestConvertCheckovToHDF_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TF_1" {
			require.NotNil(t, req.Title)
			assert.Equal(t, "Ensure Terraform module sources use a commit hash", *req.Title)
		}
	}
}

// ---- Status mapping ----

func TestConvertCheckovToHDF_StatusPassed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TF_2" {
			for _, r := range req.Results {
				assert.Equal(t, hdf.Passed, r.Status)
			}
		}
	}
}

func TestConvertCheckovToHDF_StatusFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TF_1" {
			for _, r := range req.Results {
				assert.Equal(t, hdf.Failed, r.Status)
			}
		}
	}
}

func TestConvertCheckovToHDF_StatusSkipped(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV2_AWS_6" {
			for _, r := range req.Results {
				assert.Equal(t, hdf.NotReviewed, r.Status)
			}
		}
	}
}

// ---- Skip message ----

func TestConvertCheckovToHDF_SkipMessage(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV2_AWS_6" {
			r := req.Results[0]
			require.NotNil(t, r.Message)
			assert.Contains(t, *r.Message, "Skipping public access block for demo")
		}
	}
}

// ---- CodeDesc ----

func TestConvertCheckovToHDF_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TF_1" {
			r := req.Results[0]
			assert.Contains(t, r.CodeDesc, "vpc")
		}
	}
}

// ---- Impact ----

func TestConvertCheckovToHDF_ImpactDefault(t *testing.T) {
	// No severity in open-source checkov → default 0.5
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TF_1" {
			assert.InDelta(t, 0.5, req.Impact, 0.001)
		}
	}
}

func TestConvertCheckovToHDF_ImpactFromSeverity(t *testing.T) {
	// Inline fixture with severity set
	input := []byte(`{
		"check_type": "terraform",
		"results": {
			"passed_checks": [],
			"failed_checks": [{
				"check_id": "CKV_TEST_1",
				"check_name": "Test check with critical severity",
				"check_result": {"result": "FAILED"},
				"severity": "CRITICAL",
				"file_path": "/main.tf",
				"file_line_range": [1, 5],
				"resource": "aws_s3_bucket.test",
				"guideline": null,
				"code_block": null,
				"check_class": "checkov.terraform.checks.resource.Test"
			}, {
				"check_id": "CKV_TEST_2",
				"check_name": "Test check with low severity",
				"check_result": {"result": "FAILED"},
				"severity": "LOW",
				"file_path": "/main.tf",
				"file_line_range": [6, 10],
				"resource": "aws_s3_bucket.test2",
				"guideline": null,
				"code_block": null,
				"check_class": "checkov.terraform.checks.resource.Test"
			}],
			"skipped_checks": [],
			"parsing_errors": []
		},
		"summary": {"passed": 0, "failed": 2, "skipped": 0, "parsing_errors": 0, "resource_count": 2, "checkov_version": "3.2.524"}
	}`)
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TEST_1" {
			assert.InDelta(t, 0.9, req.Impact, 0.001, "CRITICAL should map to 0.9")
		}
		if req.ID == "CKV_TEST_2" {
			assert.InDelta(t, 0.3, req.Impact, 0.001, "LOW should map to 0.3")
		}
	}
}

// ---- Descriptions ----

func TestConvertCheckovToHDF_DescriptionDefault(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TF_1" {
			defaultDesc := findDescription(req.Descriptions, "default")
			require.NotNil(t, defaultDesc, "expected a 'default' description")
			assert.Contains(t, defaultDesc.Data, "Ensure Terraform module sources use a commit hash")
		}
	}
}

func TestConvertCheckovToHDF_DescriptionCheck(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "CKV_TF_1" {
			checkDesc := findDescription(req.Descriptions, "check")
			require.NotNil(t, checkDesc, "expected a 'check' description")
			assert.Contains(t, checkDesc.Data, "prismacloud.io")
		}
	}
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- NIST tags ----

func TestConvertCheckovToHDF_NISTTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		nist, ok := req.Tags["nist"].([]string)
		require.True(t, ok, "nist tag should be []string for %s", req.ID)
		assert.Equal(t, []string{"SA-11", "RA-5"}, nist, "should use default static analysis NIST tags")
	}
}

// ---- Multi-framework ----

func TestConvertCheckovToHDF_MultiFramework(t *testing.T) {
	input := loadFixture(t, "input/multi-framework.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	// Multi-framework merges all checks into one baseline
	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "Checkov Scan", result.Baselines[0].Name)

	// Should have checks from both terraform and dockerfile
	reqs := result.Baselines[0].Requirements
	ids := make(map[string]bool)
	for _, req := range reqs {
		ids[req.ID] = true
	}
	// From terraform
	assert.True(t, ids["CKV_TF_1"], "expected terraform check CKV_TF_1")
	// From dockerfile
	assert.True(t, ids["CKV_DOCKER_7"], "expected dockerfile check CKV_DOCKER_7")
}

func TestConvertCheckovToHDF_MultiFrameworkToolFormat(t *testing.T) {
	input := loadFixture(t, "input/multi-framework.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Format)
	assert.Contains(t, *result.Tool.Format, "terraform")
	assert.Contains(t, *result.Tool.Format, "dockerfile")
}

// ---- Empty checks ----

func TestConvertCheckovToHDF_EmptyChecks(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "checkov-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Checkov")
	assert.Contains(t, req.Results[0].CodeDesc, "terraform")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

// ---- SARIF routing ----

func TestConvertCheckovToHDF_SARIFRouting(t *testing.T) {
	sarifPath := filepath.Join(shared.GetConvertersDir(), "sarif-to-hdf", "fixtures", "input", "gosec.sarif")
	input, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Skipf("SARIF fixture not found: %s", sarifPath)
	}

	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err, "SARIF input should be accepted by checkov converter")
	require.NotNil(t, result)
	require.Len(t, result.Baselines, 1)
	assert.NotEmpty(t, result.Baselines[0].Requirements)
}

// ---- Snapshot tests ----

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "checkov-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertCheckovToHDF(input, "1.0.0")
	})
}

func TestConvertCheckovToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertCheckovToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "every requirement must have verificationMethod set")
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q should be marked automated", req.ID)
	}
}
