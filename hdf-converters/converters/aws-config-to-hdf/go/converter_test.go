package awsconfig

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

// ---- ConvertAWSConfigToHDF ----

func TestConvertAWSConfigToHDF_Minimal(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "aws-config-to-hdf", "fixtures", "input", "minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read minimal.json fixture")

	result, err := ConvertAWSConfigToHDF(inputData, converterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "aws-config-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	require.Len(t, result.Baselines, 1, "Should produce one baseline")

	baseline := result.Baselines[0]
	assert.Equal(t, "AWS Config", baseline.Name)
	require.Len(t, baseline.Requirements, 1, "One requirement per ConfigRule")

	req := baseline.Requirements[0]
	assert.Equal(t, "config-rule-7hytm9", req.ID)
	assert.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "123456789012")
	assert.Contains(t, *req.Title, "access-keys-rotated")
	require.Len(t, req.Results, 2)

	// Verify NIST tags populated from SourceIdentifier
	nist, ok := req.Tags["nist"]
	assert.True(t, ok, "Should have nist tags")
	nistSlice, ok := nist.([]string)
	assert.True(t, ok)
	assert.NotEmpty(t, nistSlice)
}

func TestConvertAWSConfigToHDF_Tool(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "aws-config-to-hdf", "fixtures", "input", "minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertAWSConfigToHDF(inputData, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "AWS Config", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestConvertAWSConfigToHDF_MultiRule(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "aws-config-to-hdf", "fixtures", "input", "multi-rule.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertAWSConfigToHDF(inputData, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	baseline := result.Baselines[0]
	assert.Len(t, baseline.Requirements, 4)

	ruleIDs := make(map[string]bool)
	for _, req := range baseline.Requirements {
		ruleIDs[req.ID] = true
	}
	assert.True(t, ruleIDs["config-rule-abc123"])
	assert.True(t, ruleIDs["config-rule-def456"])
	assert.True(t, ruleIDs["config-rule-ghi789"])
	assert.True(t, ruleIDs["config-rule-jkl012"])
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "aws-config-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertAWSConfigToHDF(input, converterVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvertAWSConfigToHDF_ControlType(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "aws-config-to-hdf", "fixtures", "input", "minimal.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertAWSConfigToHDF(inputData, converterVersion)
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
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

func TestConvertAWSConfigToHDF_EmptyRules(t *testing.T) {
	input := []byte(`{"ConfigRules": []}`)
	result, err := ConvertAWSConfigToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	assert.Empty(t, result.Baselines[0].Requirements)
}

// TestConvertAWSConfigToHDF_RuleWithEmptyEvaluationResults exercises the
// live-AWS bug surfaced in issue #80 (bug 2): a Config rule that was deployed
// and active but evaluated zero in-scope resources (e.g.
// rds-cluster-multi-az-enabled in an account with no RDS clusters) must still
// produce a schema-valid requirement. The schema requires Results to have
// minItems >= 1; emitting an empty slice fails hdf validate.
//
// Semantics chosen: the rule's check ran but had no scope to evaluate, so
// the requirement is not applicable to this system. The converter
// synthesizes one NotApplicable result with a clear codeDesc.
func TestConvertAWSConfigToHDF_RuleWithEmptyEvaluationResults(t *testing.T) {
	input := []byte(`{
		"ConfigRules": [{
			"ConfigRuleId": "config-rule-zerorsrc",
			"ConfigRuleName": "rds-cluster-multi-az-enabled-zerorsrc",
			"ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-zerorsrc",
			"Description": "Checks if RDS clusters are configured for Multi-AZ.",
			"Source": {"Owner": "AWS", "SourceIdentifier": "RDS_CLUSTER_MULTI_AZ_ENABLED"},
			"InputParameters": "{}",
			"EvaluationResults": []
		}]
	}`)

	result, err := ConvertAWSConfigToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1, "empty EvaluationResults must produce exactly one synthesized result (schema minItems=1)")

	res := req.Results[0]
	assert.Equal(t, hdf.NotApplicable, res.Status, "synthesized result must be notApplicable")
	assert.Contains(t, res.CodeDesc, "zero", "codeDesc should explain that the rule found no in-scope resources")
	assert.False(t, res.StartTime.IsZero(), "StartTime must be set (schema requires the field)")
}

func TestConvertAWSConfigToHDF_MissingConfigRules(t *testing.T) {
	_, err := ConvertAWSConfigToHDF([]byte(`{}`), converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ConfigRules")
}

// ---- mapComplianceStatus ----

func TestMapComplianceStatus(t *testing.T) {
	tests := []struct {
		compliance string
		want       hdf.ResultStatus
	}{
		{"COMPLIANT", hdf.Passed},
		{"NON_COMPLIANT", hdf.Failed},
		{"NOT_APPLICABLE", hdf.NotApplicable},
		{"INSUFFICIENT_DATA", hdf.NotReviewed},
		{"UNKNOWN_VALUE", hdf.NotReviewed},
		{"", hdf.NotReviewed},
	}

	for _, tt := range tests {
		t.Run(tt.compliance, func(t *testing.T) {
			got := mapComplianceStatus(tt.compliance)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---- buildNISTTags ----

func TestBuildNISTTags_BySourceIdentifier(t *testing.T) {
	// ACCESS_KEYS_ROTATED is in the mapping
	tags := buildNISTTags("ACCESS_KEYS_ROTATED", "access-keys-rotated")
	assert.NotEmpty(t, tags)
	assert.Contains(t, tags, "AC-2(1)")
}

func TestBuildNISTTags_ByRuleNameFallback(t *testing.T) {
	// iam-user-group-membership-check is in the mapping
	tags := buildNISTTags("", "iam-user-group-membership-check")
	assert.NotEmpty(t, tags)
}

func TestBuildNISTTags_Unknown(t *testing.T) {
	tags := buildNISTTags("UNKNOWN_IDENTIFIER", "custom-not-in-mapping")
	assert.Empty(t, tags)
}

func TestBuildNISTTags_Empty(t *testing.T) {
	tags := buildNISTTags("", "")
	assert.Empty(t, tags)
}

// ---- getAccountID ----

func TestGetAccountID_ValidARN(t *testing.T) {
	arn := "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-7hytm9"
	id := getAccountID(arn)
	assert.Equal(t, "123456789012", id)
}

func TestGetAccountID_GovCloudARN(t *testing.T) {
	arn := "arn:aws-us-gov:config:us-gov-west-1:060708420889:config-rule/config-rule-7hytm9"
	id := getAccountID(arn)
	assert.Equal(t, "060708420889", id)
}

func TestGetAccountID_InvalidARN(t *testing.T) {
	id := getAccountID("not-an-arn")
	assert.Equal(t, "no-account-id", id)
}

func TestGetAccountID_EmptyARN(t *testing.T) {
	id := getAccountID("")
	assert.Equal(t, "no-account-id", id)
}

// ---- buildCheckText ----

func TestBuildCheckText_WithParams(t *testing.T) {
	rule := ConfigRule{
		ConfigRuleArn:   "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-7hytm9",
		Source:          ConfigRuleSource{SourceIdentifier: "ACCESS_KEYS_ROTATED"},
		InputParameters: `{"maxAccessKeyAge":"90"}`,
	}
	text := buildCheckText(rule)
	assert.Contains(t, text, "ARN: arn:aws:config")
	assert.Contains(t, text, "Source Identifier: ACCESS_KEYS_ROTATED")
	assert.Contains(t, text, "maxAccessKeyAge")
	assert.Contains(t, text, "<br/>")
}

func TestBuildCheckText_NoParams(t *testing.T) {
	rule := ConfigRule{
		ConfigRuleArn:   "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc",
		Source:          ConfigRuleSource{SourceIdentifier: "ROOT_ACCOUNT_MFA_ENABLED"},
		InputParameters: "{}",
	}
	text := buildCheckText(rule)
	assert.Contains(t, text, "ARN: arn:aws:config")
	assert.Contains(t, text, "Source Identifier: ROOT_ACCOUNT_MFA_ENABLED")
	assert.NotContains(t, text, "maxAccessKeyAge")
}

func TestBuildCheckText_EmptyARN(t *testing.T) {
	rule := ConfigRule{
		Source: ConfigRuleSource{SourceIdentifier: "SOME_RULE"},
	}
	text := buildCheckText(rule)
	assert.Contains(t, text, "ARN: N/A")
}

// ---- buildCodeDesc ----

func TestBuildCodeDesc(t *testing.T) {
	q := EvaluationResultQualifier{
		ConfigRuleName: "access-keys-rotated",
		ResourceType:   "AWS::IAM::User",
		ResourceID:     "AIDAQ4IUA7UM4QUIM3AGQ",
	}
	desc := buildCodeDesc(q)
	assert.Equal(t, "config_rule_name: access-keys-rotated, resource_type: AWS::IAM::User, resource_id: AIDAQ4IUA7UM4QUIM3AGQ", desc)
}

// ---- buildMessage ----

func TestBuildMessage_Failed_WithAnnotation(t *testing.T) {
	msg := buildMessage("code desc", "custom annotation", hdf.Failed)
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "(code desc)")
	assert.Contains(t, *msg, "custom annotation")
}

func TestBuildMessage_Failed_NoAnnotation(t *testing.T) {
	msg := buildMessage("code desc", "", hdf.Failed)
	require.NotNil(t, msg)
	assert.Contains(t, *msg, "Rule does not pass rule compliance")
}

func TestBuildMessage_Passed(t *testing.T) {
	msg := buildMessage("code desc", "", hdf.Passed)
	assert.Nil(t, msg)
}

func TestBuildMessage_NotApplicable(t *testing.T) {
	msg := buildMessage("code desc", "", hdf.NotApplicable)
	assert.Nil(t, msg)
}

// ---- ParseTimestamp (via shared) ----

func TestParseTimestamp_ValidRFC3339(t *testing.T) {
	ts := hdfutil.ParseTimestamp("2021-04-09T14:39:21Z")
	assert.False(t, ts.IsZero())
	assert.Equal(t, 2021, ts.Year())
	assert.Equal(t, 14, ts.Hour())
}

func TestParseTimestamp_ValidRFC3339Nano(t *testing.T) {
	ts := hdfutil.ParseTimestamp("2021-04-09T14:39:51.614Z")
	assert.False(t, ts.IsZero())
	assert.Equal(t, 51, ts.Second())
}

func TestParseTimestamp_Empty(t *testing.T) {
	ts := hdfutil.ParseTimestamp("")
	assert.True(t, ts.IsZero())
}

func TestParseTimestamp_Invalid(t *testing.T) {
	ts := hdfutil.ParseTimestamp("not-a-date")
	assert.True(t, ts.IsZero())
}

// ---- computeRunTime ----

func TestComputeRunTime_Valid(t *testing.T) {
	rt := computeRunTime("2021-04-09T14:39:21Z", "2021-04-09T14:39:51.614Z")
	require.NotNil(t, rt)
	assert.InDelta(t, 30.614, *rt, 0.001)
}

func TestComputeRunTime_EmptyStrings(t *testing.T) {
	rt := computeRunTime("", "")
	assert.Nil(t, rt)
}

func TestComputeRunTime_InvalidTimestamp(t *testing.T) {
	rt := computeRunTime("not-a-date", "2021-04-09T14:39:51Z")
	assert.Nil(t, rt)
}

// ---- Result field integration ----

func TestConvertAWSConfigToHDF_CheckDescription(t *testing.T) {
	input := []byte(`{
		"ConfigRules": [{
			"ConfigRuleId": "config-rule-test1",
			"ConfigRuleName": "access-keys-rotated",
			"ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-test1",
			"Description": "Checks access key rotation.",
			"Source": {"Owner": "AWS", "SourceIdentifier": "ACCESS_KEYS_ROTATED"},
			"InputParameters": "{\"maxAccessKeyAge\":\"90\"}",
			"EvaluationResults": []
		}]
	}`)

	result, err := ConvertAWSConfigToHDF(input, converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Descriptions, 2)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Equal(t, "Checks access key rotation.", req.Descriptions[0].Data)
	assert.Equal(t, "check", req.Descriptions[1].Label)
	assert.Contains(t, req.Descriptions[1].Data, "ARN:")
	assert.Contains(t, req.Descriptions[1].Data, "Source Identifier: ACCESS_KEYS_ROTATED")
	assert.Contains(t, req.Descriptions[1].Data, "maxAccessKeyAge")
}

func TestConvertAWSConfigToHDF_SourceLocationRef(t *testing.T) {
	arn := "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-test2"
	input := []byte(`{
		"ConfigRules": [{
			"ConfigRuleId": "config-rule-test2",
			"ConfigRuleName": "some-rule",
			"ConfigRuleArn": "` + arn + `",
			"Source": {"Owner": "AWS", "SourceIdentifier": "SOME_RULE"},
			"InputParameters": "{}",
			"EvaluationResults": []
		}]
	}`)

	result, err := ConvertAWSConfigToHDF(input, converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.NotNil(t, req.SourceLocation)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, arn, *req.SourceLocation.Ref)
}

func TestConvertAWSConfigToHDF_RunTime(t *testing.T) {
	input := []byte(`{
		"ConfigRules": [{
			"ConfigRuleId": "config-rule-test3",
			"ConfigRuleName": "access-keys-rotated",
			"ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-test3",
			"Source": {"Owner": "AWS", "SourceIdentifier": "ACCESS_KEYS_ROTATED"},
			"InputParameters": "{}",
			"EvaluationResults": [{
				"EvaluationResultIdentifier": {
					"EvaluationResultQualifier": {
						"ConfigRuleName": "access-keys-rotated",
						"ResourceType": "AWS::IAM::User",
						"ResourceId": "user-1"
					}
				},
				"ComplianceType": "COMPLIANT",
				"ConfigRuleInvokedTime": "2021-04-09T14:39:21Z",
				"ResultRecordedTime": "2021-04-09T14:39:51.614Z"
			}]
		}]
	}`)

	result, err := ConvertAWSConfigToHDF(input, converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	require.NotNil(t, req.Results[0].RunTime)
	assert.InDelta(t, 30.614, *req.Results[0].RunTime, 0.001)
}

func TestConvertAWSConfigToHDF_FailedMessage(t *testing.T) {
	input := []byte(`{
		"ConfigRules": [{
			"ConfigRuleId": "config-rule-test4",
			"ConfigRuleName": "access-keys-rotated",
			"ConfigRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-test4",
			"Source": {"Owner": "AWS", "SourceIdentifier": "ACCESS_KEYS_ROTATED"},
			"InputParameters": "{}",
			"EvaluationResults": [{
				"EvaluationResultIdentifier": {
					"EvaluationResultQualifier": {
						"ConfigRuleName": "access-keys-rotated",
						"ResourceType": "AWS::IAM::User",
						"ResourceId": "AIDAQ4IUA7UMXLY36QZXA"
					}
				},
				"ComplianceType": "NON_COMPLIANT",
				"Annotation": "Access key not rotated within 90 days",
				"ConfigRuleInvokedTime": "2021-04-09T14:39:21Z",
				"ResultRecordedTime": "2021-04-09T14:39:51.631Z"
			}]
		}]
	}`)

	result, err := ConvertAWSConfigToHDF(input, converterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	r := req.Results[0]
	assert.Equal(t, hdf.Failed, r.Status)
	require.NotNil(t, r.Message)
	assert.Contains(t, *r.Message, "config_rule_name: access-keys-rotated")
	assert.Contains(t, *r.Message, "Access key not rotated within 90 days")
}

func TestConvertAWSConfigToHDF_ChecksumIsSet(t *testing.T) {
	input := []byte(`{"ConfigRules": []}`)
	result, err := ConvertAWSConfigToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Baselines[0].Integrity)
	assert.NotEmpty(t, *result.Baselines[0].Integrity.Checksum)
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "aws-config-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertAWSConfigToHDF(input, "0.1.0")
	})
}

func TestConvertAWSConfigToHDF_VerificationMethod(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "aws-config-to-hdf", "fixtures", "input", "multi-rule.json")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertAWSConfigToHDF(inputData, converterVersion)
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
