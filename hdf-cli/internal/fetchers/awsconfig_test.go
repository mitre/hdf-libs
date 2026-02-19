package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	awsconfigconv "github.com/mitre/hdf-converters/converters/aws-config-to-hdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// ---- mock client ----

type mockConfigClient struct {
	describeRulesPages []configservice.DescribeConfigRulesOutput
	describeRulesErr   error
	// Per-rule compliance pages; keyed by rule name.
	compliancePages map[string][]configservice.GetComplianceDetailsByConfigRuleOutput
	complianceErr   error
	// Counts calls for pagination verification.
	describeCalls   int
	complianceCalls map[string]int
}

func (m *mockConfigClient) DescribeConfigRules(
	_ context.Context,
	_ *configservice.DescribeConfigRulesInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeConfigRulesOutput, error) {
	if m.describeRulesErr != nil {
		return nil, m.describeRulesErr
	}
	if m.describeCalls >= len(m.describeRulesPages) {
		return &configservice.DescribeConfigRulesOutput{}, nil
	}
	out := m.describeRulesPages[m.describeCalls]
	m.describeCalls++
	return &out, nil
}

func (m *mockConfigClient) GetComplianceDetailsByConfigRule(
	_ context.Context,
	in *configservice.GetComplianceDetailsByConfigRuleInput,
	_ ...func(*configservice.Options),
) (*configservice.GetComplianceDetailsByConfigRuleOutput, error) {
	if m.complianceErr != nil {
		return nil, m.complianceErr
	}
	name := aws.ToString(in.ConfigRuleName)
	if m.complianceCalls == nil {
		m.complianceCalls = make(map[string]int)
	}
	pages := m.compliancePages[name]
	call := m.complianceCalls[name]
	m.complianceCalls[name]++
	if call >= len(pages) {
		return &configservice.GetComplianceDetailsByConfigRuleOutput{}, nil
	}
	out := pages[call]
	return &out, nil
}

// ---- helpers ----

func mustUnmarshal(t *testing.T, data []byte) awsconfigconv.ConfigRulesFile {
	t.Helper()
	var f awsconfigconv.ConfigRulesFile
	require.NoError(t, json.Unmarshal(data, &f))
	return f
}

func ts(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// ---- tests ----

func TestAWSConfigFetcher_Fetch_NoRules(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{}},
		},
	}
	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshal(t, data)
	assert.Empty(t, result.ConfigRules)
}

func TestAWSConfigFetcher_Fetch_SingleRule(t *testing.T) {
	invokedAt := ts("2021-04-09T14:39:21Z")
	recordedAt := ts("2021-04-09T14:39:51Z")

	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{
				ConfigRules: []types.ConfigRule{
					{
						ConfigRuleId:    aws.String("config-rule-7hytm9"),
						ConfigRuleName:  aws.String("access-keys-rotated"),
						ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-7hytm9"),
						Description:     aws.String("Checks access key rotation."),
						InputParameters: aws.String(`{"maxAccessKeyAge":"90"}`),
						Source: &types.Source{
							Owner:            types.OwnerAws,
							SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED"),
						},
					},
				},
			},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"access-keys-rotated": {
				{
					EvaluationResults: []types.EvaluationResult{
						{
							EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
								EvaluationResultQualifier: &types.EvaluationResultQualifier{
									ConfigRuleName: aws.String("access-keys-rotated"),
									ResourceType:   aws.String("AWS::IAM::User"),
									ResourceId:     aws.String("AIDAQ4IUA7UM4QUIM3AGQ"),
								},
							},
							ComplianceType:        types.ComplianceTypeCompliant,
							Annotation:            nil,
							ConfigRuleInvokedTime: &invokedAt,
							ResultRecordedTime:    &recordedAt,
						},
					},
				},
			},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshal(t, data)
	require.Len(t, result.ConfigRules, 1)

	rule := result.ConfigRules[0]
	assert.Equal(t, "config-rule-7hytm9", rule.ConfigRuleID)
	assert.Equal(t, "access-keys-rotated", rule.ConfigRuleName)
	assert.Equal(t, "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-7hytm9", rule.ConfigRuleArn)
	assert.Equal(t, "Checks access key rotation.", rule.Description)
	assert.Equal(t, "ACCESS_KEYS_ROTATED", rule.Source.SourceIdentifier)
	assert.Equal(t, `{"maxAccessKeyAge":"90"}`, rule.InputParameters)

	require.Len(t, rule.EvaluationResults, 1)
	er := rule.EvaluationResults[0]
	assert.Equal(t, "access-keys-rotated", er.EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName)
	assert.Equal(t, "AWS::IAM::User", er.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType)
	assert.Equal(t, "AIDAQ4IUA7UM4QUIM3AGQ", er.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceID)
	assert.Equal(t, "COMPLIANT", er.ComplianceType)
	assert.Equal(t, "2021-04-09T14:39:21Z", er.ConfigRuleInvokedTime)
	assert.Equal(t, "2021-04-09T14:39:51Z", er.ResultRecordedTime)
}

func TestAWSConfigFetcher_Fetch_MultipleRules(t *testing.T) {
	invoked := ts("2024-02-19T00:00:05Z")
	recorded := ts("2024-02-19T00:00:15Z")

	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{
				ConfigRules: []types.ConfigRule{
					{
						ConfigRuleId:    aws.String("config-rule-abc"),
						ConfigRuleName:  aws.String("root-mfa-enabled"),
						ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc"),
						Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ROOT_ACCOUNT_MFA_ENABLED")},
						InputParameters: aws.String("{}"),
					},
					{
						ConfigRuleId:    aws.String("config-rule-def"),
						ConfigRuleName:  aws.String("s3-encryption"),
						ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-def"),
						Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED")},
						InputParameters: aws.String("{}"),
					},
				},
			},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"root-mfa-enabled": {
				{EvaluationResults: []types.EvaluationResult{
					{
						EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
							EvaluationResultQualifier: &types.EvaluationResultQualifier{
								ConfigRuleName: aws.String("root-mfa-enabled"),
								ResourceType:   aws.String("AWS::IAM::User"),
								ResourceId:     aws.String("root"),
							},
						},
						ComplianceType:        types.ComplianceTypeNonCompliant,
						Annotation:            aws.String("MFA not enabled"),
						ConfigRuleInvokedTime: &invoked,
						ResultRecordedTime:    &recorded,
					},
				}},
			},
			"s3-encryption": {
				{EvaluationResults: []types.EvaluationResult{
					{
						EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
							EvaluationResultQualifier: &types.EvaluationResultQualifier{
								ConfigRuleName: aws.String("s3-encryption"),
								ResourceType:   aws.String("AWS::S3::Bucket"),
								ResourceId:     aws.String("my-bucket"),
							},
						},
						ComplianceType:        types.ComplianceTypeCompliant,
						ConfigRuleInvokedTime: &invoked,
						ResultRecordedTime:    &recorded,
					},
				}},
			},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshal(t, data)
	require.Len(t, result.ConfigRules, 2)
	assert.Equal(t, "config-rule-abc", result.ConfigRules[0].ConfigRuleID)
	assert.Equal(t, "config-rule-def", result.ConfigRules[1].ConfigRuleID)
	assert.Len(t, result.ConfigRules[0].EvaluationResults, 1)
	assert.Equal(t, "NON_COMPLIANT", result.ConfigRules[0].EvaluationResults[0].ComplianceType)
	assert.Equal(t, "MFA not enabled", result.ConfigRules[0].EvaluationResults[0].Annotation)
}

func TestAWSConfigFetcher_Fetch_Pagination_Rules(t *testing.T) {
	invoked := ts("2024-02-19T00:00:05Z")
	recorded := ts("2024-02-19T00:00:15Z")

	// Two pages of rules — second page has no NextToken so loop stops.
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{
				ConfigRules: []types.ConfigRule{
					{
						ConfigRuleId:    aws.String("config-rule-p1"),
						ConfigRuleName:  aws.String("rule-page-one"),
						ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:111111111111:config-rule/config-rule-p1"),
						Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
						InputParameters: aws.String("{}"),
					},
				},
				NextToken: aws.String("page2token"),
			},
			{
				ConfigRules: []types.ConfigRule{
					{
						ConfigRuleId:    aws.String("config-rule-p2"),
						ConfigRuleName:  aws.String("rule-page-two"),
						ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:111111111111:config-rule/config-rule-p2"),
						Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("IAM_PASSWORD_POLICY")},
						InputParameters: aws.String("{}"),
					},
				},
				// No NextToken — end of pages.
			},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"rule-page-one": {{EvaluationResults: []types.EvaluationResult{
				{
					EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
						EvaluationResultQualifier: &types.EvaluationResultQualifier{
							ConfigRuleName: aws.String("rule-page-one"),
							ResourceType:   aws.String("AWS::IAM::User"),
							ResourceId:     aws.String("user-1"),
						},
					},
					ComplianceType:        types.ComplianceTypeCompliant,
					ConfigRuleInvokedTime: &invoked,
					ResultRecordedTime:    &recorded,
				},
			}}},
			"rule-page-two": {{EvaluationResults: []types.EvaluationResult{
				{
					EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
						EvaluationResultQualifier: &types.EvaluationResultQualifier{
							ConfigRuleName: aws.String("rule-page-two"),
							ResourceType:   aws.String("AWS::IAM::User"),
							ResourceId:     aws.String("user-2"),
						},
					},
					ComplianceType:        types.ComplianceTypeCompliant,
					ConfigRuleInvokedTime: &invoked,
					ResultRecordedTime:    &recorded,
				},
			}}},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshal(t, data)
	require.Len(t, result.ConfigRules, 2, "both pages of rules should be fetched")
	assert.Equal(t, "config-rule-p1", result.ConfigRules[0].ConfigRuleID)
	assert.Equal(t, "config-rule-p2", result.ConfigRules[1].ConfigRuleID)
}

func TestAWSConfigFetcher_Fetch_Pagination_EvaluationResults(t *testing.T) {
	invoked := ts("2024-02-19T00:00:05Z")
	recorded := ts("2024-02-19T00:00:15Z")

	// Two pages of evaluation results for the same rule.
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{
				{
					ConfigRuleId:    aws.String("config-rule-abc"),
					ConfigRuleName:  aws.String("access-keys-rotated"),
					ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc"),
					Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
					InputParameters: aws.String("{}"),
				},
			}},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"access-keys-rotated": {
				{
					EvaluationResults: []types.EvaluationResult{
						{
							EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
								EvaluationResultQualifier: &types.EvaluationResultQualifier{
									ConfigRuleName: aws.String("access-keys-rotated"),
									ResourceType:   aws.String("AWS::IAM::User"),
									ResourceId:     aws.String("user-1"),
								},
							},
							ComplianceType:        types.ComplianceTypeCompliant,
							ConfigRuleInvokedTime: &invoked,
							ResultRecordedTime:    &recorded,
						},
					},
					NextToken: aws.String("page2"),
				},
				{
					EvaluationResults: []types.EvaluationResult{
						{
							EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
								EvaluationResultQualifier: &types.EvaluationResultQualifier{
									ConfigRuleName: aws.String("access-keys-rotated"),
									ResourceType:   aws.String("AWS::IAM::User"),
									ResourceId:     aws.String("user-2"),
								},
							},
							ComplianceType:        types.ComplianceTypeNonCompliant,
							ConfigRuleInvokedTime: &invoked,
							ResultRecordedTime:    &recorded,
						},
					},
					// No NextToken — end.
				},
			},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshal(t, data)
	require.Len(t, result.ConfigRules, 1)
	assert.Len(t, result.ConfigRules[0].EvaluationResults, 2, "both pages of results should be collected")
}

func TestAWSConfigFetcher_Fetch_DescribeConfigRulesError(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesErr: fmt.Errorf("access denied"),
	}
	f := NewAWSConfigFetcherWithClient(mock)
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DescribeConfigRules")
}

func TestAWSConfigFetcher_Fetch_ComplianceError(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{
				{
					ConfigRuleId:    aws.String("config-rule-abc"),
					ConfigRuleName:  aws.String("some-rule"),
					ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc"),
					Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
					InputParameters: aws.String("{}"),
				},
			}},
		},
		complianceErr: fmt.Errorf("throttled"),
	}
	f := NewAWSConfigFetcherWithClient(mock)
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "some-rule")
}

func TestAWSConfigFetcher_Fetch_NilAnnotation(t *testing.T) {
	invoked := ts("2024-02-19T00:00:05Z")
	recorded := ts("2024-02-19T00:00:15Z")

	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{
				{
					ConfigRuleId:    aws.String("config-rule-abc"),
					ConfigRuleName:  aws.String("some-rule"),
					ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc"),
					Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
					InputParameters: aws.String("{}"),
				},
			}},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"some-rule": {{EvaluationResults: []types.EvaluationResult{
				{
					EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
						EvaluationResultQualifier: &types.EvaluationResultQualifier{
							ConfigRuleName: aws.String("some-rule"),
							ResourceType:   aws.String("AWS::IAM::User"),
							ResourceId:     aws.String("user-1"),
						},
					},
					ComplianceType:        types.ComplianceTypeCompliant,
					Annotation:            nil, // nil annotation must not panic
					ConfigRuleInvokedTime: &invoked,
					ResultRecordedTime:    &recorded,
				},
			}}},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshal(t, data)
	assert.Equal(t, "", result.ConfigRules[0].EvaluationResults[0].Annotation)
}

func TestAWSConfigFetcher_Fetch_NilTimestamps(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{
				{
					ConfigRuleId:    aws.String("config-rule-abc"),
					ConfigRuleName:  aws.String("some-rule"),
					ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc"),
					Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
					InputParameters: aws.String("{}"),
				},
			}},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"some-rule": {{EvaluationResults: []types.EvaluationResult{
				{
					EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
						EvaluationResultQualifier: &types.EvaluationResultQualifier{
							ConfigRuleName: aws.String("some-rule"),
							ResourceType:   aws.String("AWS::IAM::User"),
							ResourceId:     aws.String("user-1"),
						},
					},
					ComplianceType:        types.ComplianceTypeCompliant,
					ConfigRuleInvokedTime: nil, // nil timestamps must not panic
					ResultRecordedTime:    nil,
				},
			}}},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	result := mustUnmarshal(t, data)
	assert.Equal(t, "", result.ConfigRules[0].EvaluationResults[0].ConfigRuleInvokedTime)
	assert.Equal(t, "", result.ConfigRules[0].EvaluationResults[0].ResultRecordedTime)
}

// TestAWSConfigFetcher_FetchAndConvert verifies the fetcher output is directly
// consumable by ConvertAWSConfigToHDF — the critical end-to-end path.
func TestAWSConfigFetcher_FetchAndConvert(t *testing.T) {
	invokedAt := ts("2021-04-09T14:39:21Z")
	recordedAt := ts("2021-04-09T14:39:51Z")

	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{
				{
					ConfigRuleId:    aws.String("config-rule-7hytm9"),
					ConfigRuleName:  aws.String("access-keys-rotated"),
					ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-7hytm9"),
					Description:     aws.String("Checks access key rotation."),
					InputParameters: aws.String(`{"maxAccessKeyAge":"90"}`),
					Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
				},
			}},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"access-keys-rotated": {{EvaluationResults: []types.EvaluationResult{
				{
					EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
						EvaluationResultQualifier: &types.EvaluationResultQualifier{
							ConfigRuleName: aws.String("access-keys-rotated"),
							ResourceType:   aws.String("AWS::IAM::User"),
							ResourceId:     aws.String("AIDAQ4IUA7UM4QUIM3AGQ"),
						},
					},
					ComplianceType:        types.ComplianceTypeCompliant,
					ConfigRuleInvokedTime: &invokedAt,
					ResultRecordedTime:    &recordedAt,
				},
			}}},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	data, err := f.Fetch(context.Background())
	require.NoError(t, err)

	hdfResult, err := awsconfigconv.ConvertAWSConfigToHDF(data, "test")
	require.NoError(t, err, "fetcher output must be directly consumable by ConvertAWSConfigToHDF")
	require.Len(t, hdfResult.Baselines, 1)
	require.Len(t, hdfResult.Baselines[0].Requirements, 1)

	req := hdfResult.Baselines[0].Requirements[0]
	assert.Equal(t, "config-rule-7hytm9", req.ID)
	assert.Equal(t, hdfResult.Generator.Name, "hdf-converters")
}
