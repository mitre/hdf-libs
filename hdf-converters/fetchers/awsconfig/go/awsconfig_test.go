package awsconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	awsconfigconv "github.com/mitre/hdf-libs/hdf-converters/v3/converters/aws-config-to-hdf/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// ---- mock client ----

type mockConfigClient struct {
	t                  *testing.T // for NextToken assertions
	describeRulesPages []configservice.DescribeConfigRulesOutput
	describeRulesErr   error
	// Per-rule compliance pages; keyed by rule name.
	compliancePages map[string][]configservice.GetComplianceDetailsByConfigRuleOutput
	complianceErr   error            // returned for every rule: the fatal case
	complianceErrs  map[string]error // returned for one rule by name: the per-rule case
	// Counts calls for pagination verification.
	describeCalls   int
	complianceCalls map[string]int
	// Remediation lookups; keyed by rule name.
	remediations        map[string]types.RemediationConfiguration
	remediationErr      error            // returned for every call
	remediationBatchErr error            // returned only for a multi-name call: the all-or-nothing batch case
	remediationErrs     map[string]error // returned for a single-name call by name
	remediationBatches  [][]string       // captures each call's requested rule names
}

func (m *mockConfigClient) DescribeRemediationConfigurations(
	_ context.Context,
	in *configservice.DescribeRemediationConfigurationsInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeRemediationConfigurationsOutput, error) {
	m.remediationBatches = append(m.remediationBatches, in.ConfigRuleNames)
	if m.remediationErr != nil {
		return nil, m.remediationErr
	}
	if m.remediationBatchErr != nil && len(in.ConfigRuleNames) > 1 {
		return nil, m.remediationBatchErr
	}
	if len(in.ConfigRuleNames) == 1 {
		if err, ok := m.remediationErrs[in.ConfigRuleNames[0]]; ok {
			return nil, err
		}
	}
	var rcs []types.RemediationConfiguration
	for _, name := range in.ConfigRuleNames {
		if rc, ok := m.remediations[name]; ok {
			rcs = append(rcs, rc)
		}
	}
	return &configservice.DescribeRemediationConfigurationsOutput{RemediationConfigurations: rcs}, nil
}

func (m *mockConfigClient) DescribeConfigRules(
	_ context.Context,
	params *configservice.DescribeConfigRulesInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeConfigRulesOutput, error) {
	if m.describeRulesErr != nil {
		return nil, m.describeRulesErr
	}

	// Validate that the fetcher sends the correct NextToken for each page.
	// Call 0 should have nil; call N should carry the token from page N-1.
	if m.t != nil {
		if m.describeCalls == 0 {
			assert.Nil(m.t, params.NextToken,
				"first DescribeConfigRules call should have nil NextToken")
		} else if m.describeCalls <= len(m.describeRulesPages) {
			expected := m.describeRulesPages[m.describeCalls-1].NextToken
			assert.Equal(m.t, aws.ToString(expected), aws.ToString(params.NextToken),
				"DescribeConfigRules call %d: NextToken mismatch", m.describeCalls)
		}
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
	if err, ok := m.complianceErrs[name]; ok {
		return nil, err
	}
	if m.complianceCalls == nil {
		m.complianceCalls = make(map[string]int)
	}
	pages := m.compliancePages[name]
	call := m.complianceCalls[name]

	// Validate that the fetcher sends the correct NextToken for each page.
	if m.t != nil {
		if call == 0 {
			assert.Nil(m.t, in.NextToken,
				"first GetComplianceDetailsByConfigRule call for %s should have nil NextToken", name)
		} else if call <= len(pages) {
			expected := pages[call-1].NextToken
			assert.Equal(m.t, aws.ToString(expected), aws.ToString(in.NextToken),
				"GetComplianceDetailsByConfigRule call %d for %s: NextToken mismatch", call, name)
		}
	}

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

// ---- region validation tests ----

func TestNewAWSConfigFetcher_RegionValidation(t *testing.T) {
	ctx := context.Background()

	valid := []string{
		"us-east-1",
		"us-west-2",
		"eu-central-1",
		"ap-southeast-2",
		"us-gov-west-1",
		"cn-north-1",
		"me-south-1",
	}
	for _, r := range valid {
		t.Run("valid/"+r, func(t *testing.T) {
			// NewAWSConfigFetcher will fail past validation (no real AWS),
			// but the error must not be about region format.
			_, err := NewAWSConfigFetcher(ctx, AWSConfigParams{Region: r})
			if err != nil {
				assert.NotContains(t, err.Error(), "invalid region", "region %q should pass validation", r)
			}
		})
	}

	invalid := []string{
		"",
		"US-EAST-1",
		"us_east_1",
		"us.east.1",
		"evil.attacker.com",
		"us-east-1.evil.com",
		"us-east-1@evil.com",
		"us-east-1/path",
		"-us-east-1",
		"us-east-1-",
	}
	for _, r := range invalid {
		t.Run("invalid/"+r, func(t *testing.T) {
			_, err := NewAWSConfigFetcher(ctx, AWSConfigParams{Region: r})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid region")
		})
	}
}

// ---- pagination limit and context tests ----

// infiniteMockClient always returns a NextToken on every call, so both
// DescribeConfigRules and GetComplianceDetailsByConfigRule loop indefinitely
// unless capped by maxPages or context cancellation.
type infiniteMockClient struct{ rule types.ConfigRule }

func (m *infiniteMockClient) DescribeConfigRules(
	_ context.Context,
	_ *configservice.DescribeConfigRulesInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeConfigRulesOutput, error) {
	return &configservice.DescribeConfigRulesOutput{
		ConfigRules: []types.ConfigRule{m.rule},
		NextToken:   aws.String("forever"),
	}, nil
}

func (m *infiniteMockClient) GetComplianceDetailsByConfigRule(
	_ context.Context,
	_ *configservice.GetComplianceDetailsByConfigRuleInput,
	_ ...func(*configservice.Options),
) (*configservice.GetComplianceDetailsByConfigRuleOutput, error) {
	return &configservice.GetComplianceDetailsByConfigRuleOutput{
		NextToken: aws.String("forever"),
	}, nil
}

// oneRuleInfiniteResultsClient returns a single rule page (no NextToken) but
// returns compliance results with a NextToken on every call.
type oneRuleInfiniteResultsClient struct{ rule types.ConfigRule }

func (m *oneRuleInfiniteResultsClient) DescribeConfigRules(
	_ context.Context,
	_ *configservice.DescribeConfigRulesInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeConfigRulesOutput, error) {
	return &configservice.DescribeConfigRulesOutput{
		ConfigRules: []types.ConfigRule{m.rule},
		// No NextToken — rules loop terminates after one page.
	}, nil
}

func (m *oneRuleInfiniteResultsClient) GetComplianceDetailsByConfigRule(
	_ context.Context,
	_ *configservice.GetComplianceDetailsByConfigRuleInput,
	_ ...func(*configservice.Options),
) (*configservice.GetComplianceDetailsByConfigRuleOutput, error) {
	return &configservice.GetComplianceDetailsByConfigRuleOutput{
		NextToken: aws.String("forever"),
	}, nil
}

// contextCapturingClient wraps an inner client and records the contexts passed
// to DescribeConfigRules and GetComplianceDetailsByConfigRule so tests can
// inspect the two phases' deadlines after Fetch returns.
type contextCapturingClient struct {
	inner       ConfigServiceClient
	capturedCtx context.Context // the listing call
	readCtx     context.Context // the first compliance read
}

func (c *contextCapturingClient) DescribeConfigRules(
	ctx context.Context,
	params *configservice.DescribeConfigRulesInput,
	optFns ...func(*configservice.Options),
) (*configservice.DescribeConfigRulesOutput, error) {
	c.capturedCtx = ctx
	return c.inner.DescribeConfigRules(ctx, params, optFns...)
}

func (c *contextCapturingClient) GetComplianceDetailsByConfigRule(
	ctx context.Context,
	params *configservice.GetComplianceDetailsByConfigRuleInput,
	optFns ...func(*configservice.Options),
) (*configservice.GetComplianceDetailsByConfigRuleOutput, error) {
	if c.readCtx == nil {
		c.readCtx = ctx
	}
	return c.inner.GetComplianceDetailsByConfigRule(ctx, params, optFns...)
}

// securityHubRule is the contrast case for the readability check: provisioned by
// Security Hub and marked INTERNAL, so the API will not return its evaluations.
var securityHubRule = types.ConfigRule{
	ConfigRuleId:             aws.String("cr-sh"),
	ConfigRuleName:           aws.String("securityhub-access-keys-rotated-cce23527"),
	ConfigRuleArn:            aws.String("arn:aws:config:us-east-1:123456789012:config-rule/cr-sh"),
	Source:                   &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
	CreatedBy:                aws.String("securityhub.amazonaws.com"),
	RuleEvaluationVisibility: types.RuleEvaluationVisibilityInternal,
}

var testRule = types.ConfigRule{
	ConfigRuleId:    aws.String("config-rule-abc"),
	ConfigRuleName:  aws.String("some-rule"),
	ConfigRuleArn:   aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc"),
	Source:          &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
	InputParameters: aws.String("{}"),
}

func TestAWSConfigFetcher_PageLimit_Rules(t *testing.T) {
	f := &AWSConfigFetcher{client: &infiniteMockClient{rule: testRule}, maxPages: 3}
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum page limit")
}

func TestAWSConfigFetcher_PageLimit_EvaluationResults(t *testing.T) {
	f := &AWSConfigFetcher{client: &oneRuleInfiniteResultsClient{rule: testRule}, maxPages: 3}
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum page limit")
}

func TestAWSConfigFetcher_ContextCancelled_BeforeFirstPage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Fetch is called

	f := &AWSConfigFetcher{client: &infiniteMockClient{rule: testRule}, maxPages: 3}
	_, err := f.Fetch(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestAWSConfigFetcher_DefaultTimeoutApplied(t *testing.T) {
	// Verify that Fetch wraps a deadline-free context with a timeout by
	// capturing the context that reaches the first API call. One readable rule
	// keeps the fetch itself successful; the result is not what this test is about.
	inner := &mockConfigClient{
		t: t,
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{testRule}},
		},
	}
	ccc := &contextCapturingClient{inner: inner}

	ctx := context.Background()
	_, hasDeadline := ctx.Deadline()
	require.False(t, hasDeadline, "precondition: background context has no deadline")

	f := NewAWSConfigFetcherWithClient(ccc)
	_, err := f.Fetch(ctx)
	require.NoError(t, err)

	listDeadline, deadlineSet := ccc.capturedCtx.Deadline()
	assert.True(t, deadlineSet, "Fetch must wrap a deadline-free context with a timeout")
	readDeadline, readDeadlineSet := ccc.readCtx.Deadline()
	assert.True(t, readDeadlineSet, "the read phase must be bounded too")
	assert.True(t, readDeadline.After(listDeadline), "the read phase gets its own, longer budget sized to the listed rules")
}

// A Region near the 1000-rule cap, read one rule at a time, cannot fit in the
// listing budget; the read budget grows with the count.
func TestReadPhaseTimeout_ScalesWithRuleCount(t *testing.T) {
	assert.Equal(t, defaultFetchTimeout, readPhaseTimeout(0))
	assert.Equal(t, defaultFetchTimeout+1000*perRuleReadBudget, readPhaseTimeout(1000))
	assert.Greater(t, readPhaseTimeout(1000), 30*time.Minute, "a full Region gets well over the five-minute listing budget")
}

// A caller's own deadline is respected as given, not replaced by the defaults.
func TestAWSConfigFetcher_CallerDeadlineKept(t *testing.T) {
	inner := &mockConfigClient{describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: []types.ConfigRule{testRule}}}}
	ccc := &contextCapturingClient{inner: inner}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	want, _ := ctx.Deadline()

	_, err := NewAWSConfigFetcherWithClient(ccc).Fetch(ctx)
	require.NoError(t, err)
	got, _ := ccc.readCtx.Deadline()
	assert.Equal(t, want, got)
}

// ---- fetch tests ----

// A Region with no rules is an empty export, not an error: the array is
// present and empty (never null, which the converter rejects as a missing
// field), and whether an empty export is acceptable is the caller's call.
func TestAWSConfigFetcher_Fetch_NoRules(t *testing.T) {
	mock := &mockConfigClient{
		t: t,
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{}},
		},
	}
	data, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"ConfigRules":[]}`, string(data))
	count, _, err := awsconfigconv.ExpectedRequirementCount(data)
	require.NoError(t, err, "the converter accepts the empty export")
	assert.Zero(t, count)
}

// When every rule is unreadable the outcome is the same empty export; the
// warning, not an error, says why nothing remained.
func TestAWSConfigFetcher_Fetch_AllSkippedIsAnEmptyExport(t *testing.T) {
	internal := testRule
	internal.CreatedBy = aws.String("securityhub.amazonaws.com")
	internal.RuleEvaluationVisibility = types.RuleEvaluationVisibilityInternal
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{internal}},
		},
	}
	data, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"ConfigRules":[]}`, string(data))
	assert.Zero(t, mock.complianceCalls["some-rule"], "nothing is queried when nothing is readable")
	assert.Empty(t, mock.remediationBatches, "no remediation lookup for an empty rule set")
}

func TestAWSConfigFetcher_Fetch_SingleRule(t *testing.T) {
	invokedAt := ts("2021-04-09T14:39:21Z")
	recordedAt := ts("2021-04-09T14:39:51Z")

	mock := &mockConfigClient{
		t: t,
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
		t: t,
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
		t: t,
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
		t: t,
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
		t:                t,
		describeRulesErr: fmt.Errorf("access denied"),
	}
	f := NewAWSConfigFetcherWithClient(mock)
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DescribeConfigRules")
}

// A throttle says nothing about the rule, so it must abort the whole fetch. Two
// rules and a check on the message shape keep this test honest: with one rule a
// swallowed throttle would also end in an error naming it, via the all-failed
// path, and the test would pass while proving nothing.
func TestAWSConfigFetcher_Fetch_ComplianceError(t *testing.T) {
	mock := &mockConfigClient{
		t:                  t,
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
		complianceErr:      &smithy.GenericAPIError{Code: "ThrottlingException", Message: "throttled"},
	}
	f := NewAWSConfigFetcherWithClient(mock)
	_, err := f.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetching results for rule", "a throttle takes the abort path, not the degrade path")
	assert.NotContains(t, err.Error(), "could not be read", "the fetch must not have degraded its way to an empty result")
}

func TestAWSConfigFetcher_Fetch_NilAnnotation(t *testing.T) {
	invoked := ts("2024-02-19T00:00:05Z")
	recorded := ts("2024-02-19T00:00:15Z")

	mock := &mockConfigClient{
		t: t,
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
		t: t,
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
		t: t,
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
	assert.Equal(t, hdfResult.Generator.Name, "aws-config-to-hdf")
}

func (m *infiniteMockClient) DescribeRemediationConfigurations(
	_ context.Context,
	_ *configservice.DescribeRemediationConfigurationsInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeRemediationConfigurationsOutput, error) {
	return &configservice.DescribeRemediationConfigurationsOutput{}, nil
}

func (m *oneRuleInfiniteResultsClient) DescribeRemediationConfigurations(
	_ context.Context,
	_ *configservice.DescribeRemediationConfigurationsInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeRemediationConfigurationsOutput, error) {
	return &configservice.DescribeRemediationConfigurationsOutput{}, nil
}

func (c *contextCapturingClient) DescribeRemediationConfigurations(
	_ context.Context,
	_ *configservice.DescribeRemediationConfigurationsInput,
	_ ...func(*configservice.Options),
) (*configservice.DescribeRemediationConfigurationsOutput, error) {
	return &configservice.DescribeRemediationConfigurationsOutput{}, nil
}

// ---- remediation tests ----

func TestAWSConfigFetcher_Fetch_Remediation(t *testing.T) {
	userRule := types.ConfigRule{
		ConfigRuleId:   aws.String("cr-user"),
		ConfigRuleName: aws.String("s3-bucket-public-read-prohibited"),
		ConfigRuleArn:  aws.String("arn:aws:config:us-east-1:123456789012:config-rule/cr-user"),
		Source:         &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("S3_BUCKET_PUBLIC_READ_PROHIBITED")},
	}
	userRuleNoRem := types.ConfigRule{
		ConfigRuleId:   aws.String("cr-user2"),
		ConfigRuleName: aws.String("access-keys-rotated"),
		ConfigRuleArn:  aws.String("arn:aws:config:us-east-1:123456789012:config-rule/cr-user2"),
		Source:         &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
	}
	// A rule whose evaluations the API marks INTERNAL must stay out of the
	// remediation query so it can't poison the batch with "not supported".
	serviceLinked := securityHubRule

	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{userRule, userRuleNoRem, serviceLinked}},
		},
		remediations: map[string]types.RemediationConfiguration{
			"s3-bucket-public-read-prohibited": {
				ConfigRuleName: aws.String("s3-bucket-public-read-prohibited"),
				TargetType:     types.RemediationTargetTypeSsmDocument,
				TargetId:       aws.String("AWS-DisableS3BucketPublicReadWrite"),
				TargetVersion:  aws.String("1"),
				Automatic:      true,
			},
		},
	}

	f := NewAWSConfigFetcherWithClient(mock)
	out, err := f.Fetch(context.Background())
	require.NoError(t, err)
	file := mustUnmarshal(t, out)

	byName := map[string]awsconfigconv.ConfigRule{}
	for _, r := range file.ConfigRules {
		byName[r.ConfigRuleName] = r
	}

	// INTERNAL rule → excluded from output entirely: the API will not return its evaluations.
	require.Len(t, file.ConfigRules, 2, "an INTERNAL rule must not appear in output")
	_, present := byName["securityhub-access-keys-rotated-cce23527"]
	assert.False(t, present, "an INTERNAL rule must be excluded from output")
	for _, batch := range mock.remediationBatches {
		assert.NotContains(t, batch, "securityhub-access-keys-rotated-cce23527",
			"an INTERNAL rule must be excluded from the remediation query")
	}

	// Rule with a remediation → populated, fields carried from the SDK shape.
	rem := byName["s3-bucket-public-read-prohibited"].Remediation
	require.NotNil(t, rem, "rule with remediation should carry it")
	assert.Equal(t, "SSM_DOCUMENT", rem.TargetType)
	assert.Equal(t, "AWS-DisableS3BucketPublicReadWrite", rem.TargetID)
	assert.Equal(t, "1", rem.TargetVersion)
	assert.True(t, rem.Automatic)

	// Customer rule without a remediation → nil.
	assert.Nil(t, byName["access-keys-rotated"].Remediation)
}

func TestAWSConfigFetcher_Fetch_ConformancePackRuleIncluded(t *testing.T) {
	conformancePackRule := types.ConfigRule{
		ConfigRuleId:   aws.String("cr-cp"),
		ConfigRuleName: aws.String("ec2-volume-inuse-check-conformance-pack-abc123"),
		ConfigRuleArn:  aws.String("arn:aws:config:us-east-1:123456789012:config-rule/cr-cp"),
		Source:         &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("EC2_VOLUME_INUSE_CHECK")},
		CreatedBy:      aws.String("config-conforms.amazonaws.com"),
	}
	serviceLinked := securityHubRule

	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{conformancePackRule, serviceLinked}},
		},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"ec2-volume-inuse-check-conformance-pack-abc123": {
				{EvaluationResults: []types.EvaluationResult{
					{ComplianceType: types.ComplianceTypeCompliant},
				}},
			},
		},
		remediations: map[string]types.RemediationConfiguration{
			"ec2-volume-inuse-check-conformance-pack-abc123": {
				ConfigRuleName: aws.String("ec2-volume-inuse-check-conformance-pack-abc123"),
				TargetType:     types.RemediationTargetTypeSsmDocument,
				TargetId:       aws.String("AWS-DetachEBSVolume"),
				Automatic:      false,
			},
		},
	}

	out, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.NoError(t, err)
	file := mustUnmarshal(t, out)

	require.Len(t, file.ConfigRules, 1, "only the conformance-pack rule is readable")
	cp := file.ConfigRules[0]
	assert.Equal(t, "ec2-volume-inuse-check-conformance-pack-abc123", cp.ConfigRuleName)
	require.Len(t, cp.EvaluationResults, 1)
	assert.Equal(t, "COMPLIANT", cp.EvaluationResults[0].ComplianceType)

	require.Len(t, mock.remediationBatches, 1)
	assert.Equal(t, []string{"ec2-volume-inuse-check-conformance-pack-abc123"}, mock.remediationBatches[0],
		"a conformance-pack rule is remediation-eligible; the INTERNAL one stays out")
	require.NotNil(t, cp.Remediation, "the pack rule's remediation must land on the rule, not just be asked for")
	assert.Equal(t, "AWS-DetachEBSVolume", cp.Remediation.TargetID)
}

func TestAWSConfigFetcher_Fetch_RemediationErrorIsNonFatal(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{testRule}},
		},
		remediationErr: fmt.Errorf("throttled"),
	}
	f := NewAWSConfigFetcherWithClient(mock)
	out, err := f.Fetch(context.Background())
	require.NoError(t, err, "a remediation API error must not fail the fetch")
	file := mustUnmarshal(t, out)
	require.Len(t, file.ConfigRules, 1)
	assert.Nil(t, file.ConfigRules[0].Remediation, "no remediation on API error")
}

// Readability is the API's own signal, not who created the rule: an
// Organizations-deployed rule with EXTERNAL visibility is readable, a Security
// Hub rule with INTERNAL visibility is not, and a rule carrying no visibility
// value (older API responses) is treated as readable rather than dropped.
func TestAWSConfigFetcher_ReadabilityFollowsEvaluationVisibility(t *testing.T) {
	mk := func(id, name, createdBy string, vis types.RuleEvaluationVisibility) types.ConfigRule {
		return types.ConfigRule{
			ConfigRuleId:             aws.String(id),
			ConfigRuleName:           aws.String(name),
			ConfigRuleArn:            aws.String("arn:aws:config:us-east-1:123456789012:config-rule/" + id),
			Source:                   &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("ACCESS_KEYS_ROTATED")},
			CreatedBy:                aws.String(createdBy),
			RuleEvaluationVisibility: vis,
		}
	}
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: []types.ConfigRule{
			mk("cr-org", "org-managed-rule", "organizations.amazonaws.com", types.RuleEvaluationVisibilityExternal),
			mk("cr-sh", "securityhub-rule", "securityhub.amazonaws.com", types.RuleEvaluationVisibilityInternal),
			mk("cr-cp", "pack-rule", "config-conforms.amazonaws.com", ""),
		}}},
	}

	rules, skipped, err := NewAWSConfigFetcherWithClient(mock).fetchAllConfigRules(context.Background())
	require.NoError(t, err)
	require.Len(t, skipped, 1, "only the INTERNAL rule is unreadable")
	assert.Equal(t, UnreadableRule{Name: "securityhub-rule", Detail: "securityhub.amazonaws.com"}, skipped[0],
		"the warning names the rule and the service that provisioned it")
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.ConfigRuleName)
	}
	assert.ElementsMatch(t, []string{"org-managed-rule", "pack-rule"}, names)
}

// twoRules is a page with one readable rule whose compliance read will succeed
// and a second whose read the mock fails by name.
func twoRules() []types.ConfigRule {
	second := testRule
	second.ConfigRuleId = aws.String("config-rule-def")
	second.ConfigRuleName = aws.String("other-rule")
	return []types.ConfigRule{testRule, second}
}

// A rule the API will not let this principal read, or that vanished between
// listing and reading, must cost that one rule and a warning, not the fetch.
// The refusal cases come after a rule that read, which is what makes them
// per-rule rather than a principal that cannot read anything.
func TestAWSConfigFetcher_Fetch_PerRuleReadFailureDegrades(t *testing.T) {
	for name, perRule := range map[string]error{
		"not found":               &types.NoSuchConfigRuleException{Message: aws.String("gone")},
		"insufficient permission": &types.InsufficientPermissionsException{Message: aws.String("denied")},
		"access denied":           &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"},
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockConfigClient{
				describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
				complianceErrs:     map[string]error{"other-rule": perRule},
			}
			out, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
			require.NoError(t, err, "one unreadable rule must not abort the fetch")
			file := mustUnmarshal(t, out)
			require.Len(t, file.ConfigRules, 1, "the rule that failed to read is dropped, not emitted empty")
			assert.Equal(t, "some-rule", file.ConfigRules[0].ConfigRuleName)
		})
	}
}

// Errors that say nothing about the rule stay fatal: a throttle or a dead
// network is not a reason to report a partial document as the account's state.
func TestAWSConfigFetcher_Fetch_OtherPerRuleErrorsStayFatal(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
		complianceErrs:     map[string]error{"other-rule": &smithy.GenericAPIError{Code: "ThrottlingException", Message: "slow down"}},
	}
	_, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "other-rule")
}

// A refusal before any rule has read is a principal that lacks the read
// permission altogether: one clear error, not a failed call per rule and a
// thousand-entry warning.
func TestAWSConfigFetcher_Fetch_RefusalBeforeAnyReadIsFatal(t *testing.T) {
	for name, refusal := range map[string]error{
		"insufficient permission": &types.InsufficientPermissionsException{Message: aws.String("denied")},
		"access denied":           &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"},
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockConfigClient{
				describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
				complianceErrs:     map[string]error{"some-rule": refusal},
			}
			_, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "some-rule")
			assert.Contains(t, err.Error(), "config:GetComplianceDetailsByConfigRule", "the error names the permission to grant")
			assert.Zero(t, mock.complianceCalls["other-rule"], "the fetch stops at the first refusal")
		})
	}
}

// When every listed rule has vanished the outcome composes with the empty
// export: an empty array and a warning, never a null document or an error.
func TestAWSConfigFetcher_Fetch_AllRulesGoneIsAnEmptyExport(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: []types.ConfigRule{testRule}}},
		complianceErrs:     map[string]error{"some-rule": &types.NoSuchConfigRuleException{Message: aws.String("gone")}},
	}
	data, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"ConfigRules":[]}`, string(data))
}

// A remediation batch is all-or-nothing, so one name the API refuses must not
// cost the other rules in its batch their fix: the batch is retried one name at
// a time and only the refused rule goes without.
func TestAWSConfigFetcher_Fetch_RemediationBatchFailureRetriesPerRule(t *testing.T) {
	mk := func(id, name string) types.ConfigRule {
		r := testRule
		r.ConfigRuleId, r.ConfigRuleName = aws.String(id), aws.String(name)
		return r
	}
	pack := mk("cr-cp", "pack-rule")
	pack.CreatedBy = aws.String("config-conforms.amazonaws.com")
	rules := []types.ConfigRule{mk("cr-1", "rule-1"), mk("cr-2", "rule-2"), mk("cr-3", "rule-3"), pack}
	rc := func(name string) types.RemediationConfiguration {
		return types.RemediationConfiguration{
			ConfigRuleName: aws.String(name), TargetType: types.RemediationTargetTypeSsmDocument,
			TargetId: aws.String("AWS-FixIt"), TargetVersion: aws.String("1"),
		}
	}
	mock := &mockConfigClient{
		describeRulesPages:  []configservice.DescribeConfigRulesOutput{{ConfigRules: rules}},
		remediations:        map[string]types.RemediationConfiguration{"rule-1": rc("rule-1"), "rule-2": rc("rule-2"), "rule-3": rc("rule-3")},
		remediationBatchErr: &smithy.GenericAPIError{Code: "InvalidParameterValueException", Message: "pack-rule is service linked"},
		remediationErrs:     map[string]error{"pack-rule": &smithy.GenericAPIError{Code: "InvalidParameterValueException", Message: "pack-rule is service linked"}},
	}
	out, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.NoError(t, err)
	file := mustUnmarshal(t, out)
	require.Len(t, file.ConfigRules, 4)
	byName := map[string]*awsconfigconv.RemediationConfiguration{}
	for _, r := range file.ConfigRules {
		byName[r.ConfigRuleName] = r.Remediation
	}
	for _, name := range []string{"rule-1", "rule-2", "rule-3"} {
		require.NotNil(t, byName[name], "%s keeps its remediation despite the failed batch", name)
		assert.Equal(t, "AWS-FixIt", byName[name].TargetID)
	}
	assert.Nil(t, byName["pack-rule"], "only the refused rule goes without")
	require.Len(t, mock.remediationBatches, 5, "one failed batch of four, then four single-name retries")
	assert.Len(t, mock.remediationBatches[0], 4)
}

// Every rule in the account came from a conformance pack. It must go all the
// way through the converter and produce requirements, not stop at the fetcher
// or at the converter's required-field check.
func TestAWSConfigFetcher_PackOnlyAccount_ConvertsEndToEnd(t *testing.T) {
	invokedAt := ts("2021-04-09T14:39:21Z")
	recordedAt := ts("2021-04-09T14:39:51Z")
	packRule := types.ConfigRule{
		ConfigRuleId:   aws.String("config-rule-cp1"),
		ConfigRuleName: aws.String("ec2-volume-inuse-check-conformance-pack-abc123"),
		ConfigRuleArn:  aws.String("arn:aws:config:us-east-1:123456789012:config-rule/config-rule-cp1"),
		Source:         &types.Source{Owner: types.OwnerAws, SourceIdentifier: aws.String("EC2_VOLUME_INUSE_CHECK")},
		CreatedBy:      aws.String("config-conforms.amazonaws.com"),
	}
	mock := &mockConfigClient{
		t:                  t,
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: []types.ConfigRule{packRule}}},
		compliancePages: map[string][]configservice.GetComplianceDetailsByConfigRuleOutput{
			"ec2-volume-inuse-check-conformance-pack-abc123": {{EvaluationResults: []types.EvaluationResult{{
				EvaluationResultIdentifier: &types.EvaluationResultIdentifier{
					EvaluationResultQualifier: &types.EvaluationResultQualifier{
						ConfigRuleName: aws.String("ec2-volume-inuse-check-conformance-pack-abc123"),
						ResourceType:   aws.String("AWS::EC2::Volume"),
						ResourceId:     aws.String("vol-0123456789abcdef0"),
					},
				},
				ComplianceType:        types.ComplianceTypeNonCompliant,
				ConfigRuleInvokedTime: &invokedAt,
				ResultRecordedTime:    &recordedAt,
			}}}},
		},
	}

	data, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.NoError(t, err, "a pack-only account must fetch")
	hdfResult, err := awsconfigconv.ConvertAWSConfigToHDF(data, "test")
	require.NoError(t, err, "a pack-only fetch must convert")
	require.Len(t, hdfResult.Baselines, 1)
	require.Len(t, hdfResult.Baselines[0].Requirements, 1)
	assert.Equal(t, "config-rule-cp1", hdfResult.Baselines[0].Requirements[0].ID)
}

// ---- grouped warning tests ----

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	os.Stderr = old
	require.NoError(t, w.Close())
	return <-done
}

// rulesNamed is one page of readable rules with the given names.
func rulesNamed(names ...string) []types.ConfigRule {
	rules := make([]types.ConfigRule, len(names))
	for i, name := range names {
		rules[i] = testRule
		rules[i].ConfigRuleId = aws.String("cr-" + name)
		rules[i].ConfigRuleName = aws.String(name)
	}
	return rules
}

// liveReadError shapes an API exception the way the SDK delivers one over HTTP:
// inside the operation error and a response error whose request ID differs on
// every call, so two reads refused for the same reason never share an Error().
func liveReadError(requestID string, apiErr error) error {
	return &smithy.OperationError{
		ServiceID:     "Config Service",
		OperationName: "GetComplianceDetailsByConfigRule",
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 400}},
				Err:      apiErr,
			},
			RequestID: requestID,
		},
	}
}

func gone() error { return &types.NoSuchConfigRuleException{Message: aws.String("gone")} }

// Three rules lost to the same cause: the warning names the cause once and each
// rule once, even though the three errors differ in their request IDs.
func TestAWSConfigFetcher_Fetch_RepeatedCauseIsNamedOnce(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: rulesNamed("rule-a", "rule-b", "rule-c")}},
		complianceErrs: map[string]error{
			"rule-a": liveReadError("req-1", gone()),
			"rule-b": liveReadError("req-2", gone()),
			"rule-c": liveReadError("req-3", gone()),
		},
	}
	var data []byte
	var err error
	stderr := captureStderr(t, func() { data, err = NewAWSConfigFetcherWithClient(mock).Fetch(context.Background()) })
	require.NoError(t, err)
	assert.JSONEq(t, `{"ConfigRules":[]}`, string(data))
	assert.Equal(t, "WARNING: aws-config: 3 rule(s) could not be read and were dropped: "+
		"rule-a, rule-b, rule-c (NoSuchConfigRuleException: gone)\n", stderr)
}

// Different causes are grouped by cause in the order each was first seen. The
// refusal comes after rule-a has read, which is what makes it per-rule.
func TestAWSConfigFetcher_Fetch_DifferentCausesAreGrouped(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: rulesNamed("rule-a", "rule-b", "rule-c", "rule-d")}},
		complianceErrs: map[string]error{
			"rule-b": liveReadError("req-1", gone()),
			"rule-c": liveReadError("req-2", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}),
			"rule-d": liveReadError("req-3", gone()),
		},
	}
	var data []byte
	var err error
	stderr := captureStderr(t, func() { data, err = NewAWSConfigFetcherWithClient(mock).Fetch(context.Background()) })
	require.NoError(t, err)
	require.Len(t, mustUnmarshal(t, data).ConfigRules, 1)
	assert.Equal(t, "WARNING: aws-config: 3 rule(s) could not be read and were dropped: "+
		"rule-b, rule-d (NoSuchConfigRuleException: gone); rule-c (AccessDeniedException: not authorized)\n", stderr)
}

// A partial fetch is visible to the caller, not only on stderr: the result names
// each dropped rule with its cause and leaves reporting to the caller that asked.
func TestAWSConfigFetcher_FetchWithReport_ExposesDroppedRules(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
		complianceErrs:     map[string]error{"other-rule": liveReadError("req-1", gone())},
	}
	var res FetchResult
	var err error
	stderr := captureStderr(t, func() { res, err = NewAWSConfigFetcherWithClient(mock).FetchWithReport(context.Background()) })
	require.NoError(t, err)
	assert.Empty(t, stderr, "the caller that asked for the report owns the warning")
	assert.Equal(t, []UnreadableRule{{Name: "other-rule", Detail: "NoSuchConfigRuleException: gone"}}, res.Dropped)
	file := mustUnmarshal(t, res.Data)
	require.Len(t, file.ConfigRules, 1)
	assert.Equal(t, "some-rule", file.ConfigRules[0].ConfigRuleName)
	assert.Equal(t, "WARNING: aws-config: 1 rule(s) could not be read and were dropped: other-rule (NoSuchConfigRuleException: gone)",
		DroppedWarning(res.Dropped))
}

// A clean fetch reports nothing dropped and has no warning to print.
func TestAWSConfigFetcher_FetchWithReport_CleanFetchDropsNothing(t *testing.T) {
	mock := &mockConfigClient{describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}}}
	res, err := NewAWSConfigFetcherWithClient(mock).FetchWithReport(context.Background())
	require.NoError(t, err)
	assert.Empty(t, res.Dropped)
	assert.Empty(t, DroppedWarning(res.Dropped))
	require.Len(t, mustUnmarshal(t, res.Data).ConfigRules, 2)
}

// Rules sharing a detail are listed once under it, groups keep first-seen order,
// and a rule with no detail is named bare.
func TestDescribeUnreadable_GroupsByDetail(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []UnreadableRule
		want string
	}{
		"none":        {nil, ""},
		"one":         {[]UnreadableRule{{Name: "a", Detail: "x"}}, "a (x)"},
		"same detail": {[]UnreadableRule{{Name: "a", Detail: "x"}, {Name: "b", Detail: "x"}}, "a, b (x)"},
		"mixed":       {[]UnreadableRule{{Name: "a", Detail: "x"}, {Name: "b", Detail: "y"}, {Name: "c", Detail: "x"}}, "a, c (x); b (y)"},
		"no detail":   {[]UnreadableRule{{Name: "a"}, {Name: "b"}}, "a, b"},
	} {
		t.Run(name, func(t *testing.T) { assert.Equal(t, tc.want, describeUnreadable(tc.in)) })
	}
}

// The remediation warning renders through the same grouping, so two rules whose
// remediation lookup was refused for one reason name that reason once.
func TestAWSConfigFetcher_Remediations_RefusalsGroupByCause(t *testing.T) {
	refused := liveReadError("req-1", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"})
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: rulesNamed("rule-a", "rule-b")}},
		remediationErr:     refused,
	}
	stderr := captureStderr(t, func() {
		_, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
		require.NoError(t, err)
	})
	assert.Equal(t, "WARNING: aws-config: skipping remediation for 2 rule(s): "+
		"rule-a, rule-b (AccessDeniedException: not authorized)\n", stderr)
}

// The warning for rules the API marks unreadable is the user's only record that
// they were left out, so its wording is pinned rather than left to inspection.
func TestAWSConfigFetcher_Fetch_SkipWarningNamesTheRules(t *testing.T) {
	internal := testRule
	internal.ConfigRuleId = aws.String("cr-sh")
	internal.ConfigRuleName = aws.String("securityhub-rule")
	internal.CreatedBy = aws.String("securityhub.amazonaws.com")
	internal.RuleEvaluationVisibility = types.RuleEvaluationVisibilityInternal
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{testRule, internal}},
		},
	}
	stderr := captureStderr(t, func() {
		_, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
		require.NoError(t, err)
	})
	assert.Equal(t, "WARNING: aws-config: skipped 1 rule(s) whose evaluations the Config API will not "+
		"return (RuleEvaluationVisibility INTERNAL): securityhub-rule (securityhub.amazonaws.com)\n", stderr)
}

// A request the service rejects as malformed is about the one rule the request
// names, so it costs that rule — but only once some rule has read, because a
// rejection before any success is more likely a request this fetcher built
// wrongly for every rule than a thousand individually bad rule names.
func TestAWSConfigFetcher_Fetch_RejectedRequestCostsThatRule(t *testing.T) {
	for name, rejection := range map[string]error{
		"validation":    &types.ValidationException{Message: aws.String("not valid")},
		"invalid param": &types.InvalidParameterValueException{Message: aws.String("bad parameter")},
		"generic 4xx":   &smithy.GenericAPIError{Code: "ValidationException", Message: "not valid"},
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockConfigClient{
				describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
				complianceErrs:     map[string]error{"other-rule": liveReadError("req-1", rejection)},
			}
			var out []byte
			var err error
			stderr := captureStderr(t, func() {
				out, err = NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
			})
			require.NoError(t, err, "one rejected rule must not abort the fetch")
			file := mustUnmarshal(t, out)
			require.Len(t, file.ConfigRules, 1)
			assert.Equal(t, "some-rule", file.ConfigRules[0].ConfigRuleName)
			assert.Contains(t, stderr, "other-rule", "the warning names the rule that was dropped")
		})
	}
}

// Rejected before any rule has read: the request shape is suspect, so the fetch
// fails naming that rather than reporting every rule as unreadable.
func TestAWSConfigFetcher_Fetch_RejectionBeforeAnyReadIsFatal(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
		complianceErrs: map[string]error{
			"some-rule":  liveReadError("req-1", &types.ValidationException{Message: aws.String("not valid")}),
			"other-rule": liveReadError("req-2", &types.ValidationException{Message: aws.String("not valid")}),
		},
	}
	_, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "some-rule")
	assert.Contains(t, err.Error(), "no rule has read yet")
}

// A server-side failure says nothing about the rule and always aborts.
func TestAWSConfigFetcher_Fetch_ServerErrorsStayFatal(t *testing.T) {
	for name, fatal := range map[string]error{
		"internal":    &smithy.GenericAPIError{Code: "InternalServerException", Message: "boom"},
		"unavailable": &smithy.GenericAPIError{Code: "ServiceUnavailable", Message: "later"},
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockConfigClient{
				describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
				complianceErrs:     map[string]error{"other-rule": liveReadError("req-1", fatal)},
			}
			_, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "other-rule")
		})
	}
}

// A rule the response leaves without a visibility value is attempted, and what
// its read returns decides its fate like any other rule's.
func TestAWSConfigFetcher_Fetch_UnsetVisibilityIsAttempted(t *testing.T) {
	serviceRule := testRule
	serviceRule.ConfigRuleId = aws.String("cr-svc")
	serviceRule.ConfigRuleName = aws.String("service-rule")
	serviceRule.CreatedBy = aws.String("securityhub.amazonaws.com")
	serviceRule.RuleEvaluationVisibility = ""
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{
			{ConfigRules: []types.ConfigRule{testRule, serviceRule}},
		},
	}
	out, err := NewAWSConfigFetcherWithClient(mock).Fetch(context.Background())
	require.NoError(t, err)
	require.Len(t, mustUnmarshal(t, out).ConfigRules, 2, "an unset visibility is read, not skipped")
	assert.Positive(t, mock.complianceCalls["service-rule"], "its evaluations were asked for")
}

// A deadline already past aborts rather than reporting every rule as unreadable:
// the context says nothing about any rule.
func TestAWSConfigFetcher_Fetch_PassedDeadlineIsFatal(t *testing.T) {
	mock := &mockConfigClient{
		describeRulesPages: []configservice.DescribeConfigRulesOutput{{ConfigRules: twoRules()}},
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := NewAWSConfigFetcherWithClient(mock).Fetch(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
